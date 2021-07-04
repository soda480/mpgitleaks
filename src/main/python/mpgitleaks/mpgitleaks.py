
import os
import re
import logging
import subprocess
import argparse
import shutil
from pathlib import Path
from multiprocessing import Queue
from queue import Empty

from github3api import GitHubAPI
from mp4ansi import MP4ansi

logger = logging.getLogger(__name__)

HOME = '/opt/mpgitleaks'
MAX_PROCESSES = 35


def get_parser():
    """ return argument parser
    """
    parser = argparse.ArgumentParser(
        description='A Python script that wraps the gitleaks tool to enable scanning of multiple repositories in parallel')
    parser.add_argument(
        '--file',
        dest='filename',
        type=str,
        default='repos.txt',
        required=False,
        help='file containing repositories to process')
    parser.add_argument(
        '--user',
        dest='user',
        action='store_true',
        help='process repos for the authenticated user')
    parser.add_argument(
        '--org',
        dest='org',
        type=str,
        default=None,
        required=False,
        help='process repos for the specified GitHub organization')
    parser.add_argument(
        '--exclude',
        dest='exclude',
        type=str,
        default='',
        required=False,
        help='a regex to match name of repos to exclude from processing')
    parser.add_argument(
        '--include',
        dest='include',
        type=str,
        default='',
        required=False,
        help='a regex to match name of repos to include in processing')
    parser.add_argument(
        '--progress',
        dest='progress',
        action='store_true',
        help='display progress bar for each process')
    return parser


def configure_logging():
    """ configure logging
    """
    rootLogger = logging.getLogger()
    rootLogger.setLevel(logging.DEBUG)
    file_handler = logging.FileHandler('mpgitleaks.log')
    file_formatter = logging.Formatter("%(asctime)s %(processName)s [%(funcName)s] %(levelname)s %(message)s")
    file_handler.setFormatter(file_formatter)
    rootLogger.addHandler(file_handler)


def echo(message):
    """ print and log message
    """
    logger.debug(message)
    print(message)


def get_client():
    """ return instance of GitHubAPI RESTclient
    """
    if not os.getenv('GH_TOKEN_PSW'):
        raise ValueError('GH_TOKEN_PSW environment variable must be set to token')
    return GitHubAPI.get_client()


def execute_command(command, **kwargs):
    """ execute command
    """
    command_split = command.split(' ')
    logger.debug(f'executing command: {command}')
    process = subprocess.run(command_split, capture_output=True, text=True, **kwargs)
    logger.debug(f'executed command: {command}')
    logger.debug(f'returncode: {process.returncode}')
    if process.stdout:
        logger.debug(f'stdout:\n{process.stdout}')
    if process.stderr:
        logger.debug(f'stderr:\n{process.stderr}')
    return process.returncode


def get_repo_data(ssh_urls):
    """ return list of repo data from addresses
    """
    repos = []
    for ssh_url in ssh_urls:
        owner = ssh_url.split(':')[1].split('/')[0]
        name = ssh_url.split('/')[-1].replace('.git', '')
        item = {
            'ssh_url': ssh_url,
            'full_name': f'{owner}/{name}'
        }
        repos.append(item)
    return repos


def create_directories():
    """ create required directories
    """
    scans_dir = f"{os.getenv('PWD', HOME)}/scans"
    dirs = {
        'scans': scans_dir,
        'clones': f'{scans_dir}/clones',
        'reports': f'{scans_dir}/reports'
    }
    for _, value in dirs.items():
        Path(value).mkdir(parents=True, exist_ok=True)
    return dirs


def scan_repo(process_data, *args):
    """ execute gitleaks scan on all branches of repo pulled from queue
    """
    repo_ssh_url = process_data['ssh_url']
    repo_full_name = process_data['full_name']
    repo_name = repo_full_name.replace('/', '-')

    logger.debug(f'processing repo {repo_full_name}')

    client = get_client()
    branches = client.get(f'/repos/{repo_full_name}/branches', _get='all', _attributes=['name'])
    logger.debug(f'processing total of {len(branches) * 2 + 1} commands for repo {repo_full_name}')

    dirs = create_directories()

    clone_dir = f"{dirs['clones']}/{repo_name}"
    shutil.rmtree(clone_dir, ignore_errors=True)
    execute_command(f'git clone {repo_ssh_url} {repo_name}', cwd=dirs['clones'])

    result = {}
    for branch in branches:
        branch_name = branch['name']
        logger.debug(f'processing branch {branch_name} for repo {repo_full_name}')
        execute_command(f'git checkout -b {branch_name} origin/{branch_name}', cwd=clone_dir)
        safe_branch_name = branch_name.replace('/', '-')
        report = f"{dirs['reports']}/{repo_name}-{safe_branch_name}.json"
        exit_code = execute_command(f'gitleaks --path=. --branch={branch_name} --report={report} --threads=10', cwd=clone_dir)
        result[f'{repo_full_name}:{branch_name}'] = False if exit_code == 0 else report
        logger.debug(f'processing of branch {branch_name} for repo {repo_full_name} is complete')

    logger.debug(f'processing of repo {repo_full_name} complete')
    return result


def scan_repo_queue(process_data, *args):
    """ execute gitleaks scan on all branches of repo pulled from queue
    """
    repo_queue = process_data['repo_queue']
    dirs = create_directories()
    client = get_client()
    zfill = len(str(repo_queue.qsize()))
    result = {}
    repo_count = 0
    while True:
        try:
            repo = repo_queue.get(timeout=10)

            repo_ssh_url = repo['ssh_url']
            repo_full_name = repo['full_name']
            repo_name = repo_full_name.replace('/', '-')

            repo_count += 1
            logger.debug(f'processing repo {repo_full_name}')

            branches = client.get(f'/repos/{repo_full_name}/branches', _get='all', _attributes=['name'])
            logger.debug(f'processing total of {len(branches) * 2 + 1} commands for repo {repo_full_name}')

            clone_dir = f"{dirs['clones']}/{repo_name}"
            shutil.rmtree(clone_dir, ignore_errors=True)
            execute_command(f'git clone {repo_ssh_url} {repo_name}', cwd=dirs['clones'])

            for branch in branches:
                branch_name = branch['name']
                logger.debug(f'processing branch {branch_name} for repo {repo_full_name}')
                execute_command(f'git checkout -b {branch_name} origin/{branch_name}', cwd=clone_dir)
                safe_branch_name = branch_name.replace('/', '-')
                report = f"{dirs['reports']}/{repo_name}-{safe_branch_name}.json"
                exit_code = execute_command(f'gitleaks --path=. --branch={branch_name} --report={report} --threads=10', cwd=clone_dir)
                result[f'{repo_full_name}:{branch_name}'] = False if exit_code == 0 else report
                logger.debug(f'processing of branch {branch_name} for repo {repo_full_name} is complete')

            logger.debug(f'processing of repo {repo_full_name} complete')

        except Empty:
            logger.debug('repo queue is empty')
            break
    logger.debug(f'processing of repos complete - scanned {str(repo_count).zfill(zfill)} repos')
    return result


def get_results(process_data):
    """ return results
    """
    results = {}
    for process in process_data:
        results.update(process['result'])
    return results


def get_process_data_queue(repos):
    """ get process data for queue processing
    """
    repo_queue = Queue()
    for repo in repos:
        repo_queue.put(repo)
    process_data = []
    for _ in range(MAX_PROCESSES):
        item = {
            'repo_queue': repo_queue
        }
        process_data.append(item)
    return process_data


def execute_scans(repos, progress):
    """ return process data for multiprocessing
    """
    if not repos:
        raise ValueError('no repos to process')

    if len(repos) <= MAX_PROCESSES:
        function = scan_repo
        process_data = repos
        max_length = max(len(item['full_name']) for item in repos)
        config = {
            'id_regex': r'^processing repo (?P<value>.*)$',
            'id_justify': True,
            'id_width': max_length,
        }
        if progress:
            config['progress_bar'] = {
                'total': r'^processing total of (?P<value>\d+) commands for repo .*$',
                'count_regex': r'^executed command: (?P<value>.*)$',
                'progress_message': 'scanning of all branches complete'
            }
    else:
        config = {
            'text_regex': r'processing|executing'
        }
        function = scan_repo_queue
        process_data = get_process_data_queue(repos)

    mp4ansi = MP4ansi(function=function, process_data=process_data, config=config)
    mp4ansi.execute(raise_if_error=True)
    return get_results(process_data)


def get_file_repos(filename):
    """ return list of repos read from filename
    """
    echo(f'Getting repos from file {filename}...')
    if not os.access(filename, os.R_OK):
        raise ValueError(f"the default repos file '{filename}' cannot be read")
    with open(filename) as infile:
        ssh_urls = [line.strip() for line in infile.readlines()]
    repos = get_repo_data(ssh_urls)
    return repos


def get_user_repos(client):
    """ return repos for authenticated user
    """
    user = client.get('/user')['login']
    echo(f'Getting repos for the authenticated user {user}... this may take awhile')
    repos = client.get('/user/repos', _get='all', _attributes=['full_name', 'ssh_url'])
    return repos


def get_org_repos(client, org):
    """ return repos for organization
    """
    echo(f'Getting repos for org {org}... this may take awhile')
    repos = client.get(f'/orgs/{org}/repos', _get='all', _attributes=['full_name', 'ssh_url'])
    return repos


def get_repos(filename, user, org):
    """ get repos for filename, user or org
    """
    client = get_client()
    if user:
        repos = get_user_repos(client)
    elif org:
        repos = get_org_repos(client, org)
    else:
        repos = get_file_repos(filename)
    return repos


def match_criteria(name, include, exclude):
    """ return tuple match include and exclude on name
    """
    match_include = True
    match_exclude = False
    if include:
        match_include = re.match(include, name)
    if exclude:
        match_exclude = re.match(exclude, name)
    return match_include, match_exclude


def match_repos(repos, include, exclude):
    """ match repos using include and exclude regex
    """
    logger.debug(f'matching repos using include {include} and exclude {exclude}')
    matched_repos = []
    for repo in repos:
        repo_name = repo['full_name']
        match_include, match_exclude = match_criteria(repo_name, include, exclude)
        if match_include and not match_exclude:
            matched_repos.append(repo)
    echo(f'A total of {len(matched_repos)} repos will be processed per the specified inclusion and exclusion criteria')
    return matched_repos


def display_results(results):
    """ print results
    """
    if any(results.values()):
        echo('The following repos failed gitleaks scan:')
        for scan, report in results.items():
            if report:
                home_dir = os.getenv('PWD', HOME)
                relative = report.replace(home_dir, '.')
                echo(f"{scan}:\n   {relative}")
    else:
        echo('All branches in all repos passed gitleaks scan')


def main():
    """ main function
    """
    args = get_parser().parse_args()
    configure_logging()
    repos = get_repos(args.filename, args.user, args.org)
    matched_repos = match_repos(repos, args.include, args.exclude)
    results = execute_scans(matched_repos, args.progress)
    display_results(results)


if __name__ == '__main__':
    main()
