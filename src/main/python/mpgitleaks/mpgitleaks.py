
import os
import re
import logging
import subprocess
import argparse
import shutil
from pathlib import Path

from github3api import GitHubAPI
from mp4ansi import MP4ansi

logger = logging.getLogger(__name__)

HOME = '/opt/mpgitleaks'


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


def get_file_repos(filename):
    """ return list of repos read from filename
    """
    if not os.access(filename, os.R_OK):
        raise ValueError(f"the default repos file '{filename}' cannot be read")
    with open(filename) as infile:
        ssh_urls = [line.strip() for line in infile.readlines()]
    repos = get_repo_data(ssh_urls)
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
    for key, value in dirs.items():
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
        report = f"{dirs['reports']}/{repo_name}-{branch_name}.json"
        exit_code = execute_command(f'gitleaks --path=. --branch={branch_name} --report={report} --threads=10', cwd=clone_dir)
        result[f'{repo_full_name}:{branch_name}'] = False if exit_code == 0 else report
        logger.debug(f'processing of branch {branch_name} for repo {repo_full_name} is complete')

    logger.debug(f'processing of repo {repo_full_name} complete')
    return result


def get_results(process_data):
    """ return results
    """
    results = {}
    for process in process_data:
        results.update(process['result'])
    return results


def execute_scans(repos, progress):
    """ return process data for multiprocessing
    """
    if not repos:
        raise ValueError('no repos to process')
    process_data = repos
    max_length = max(len(item['full_name']) for item in process_data)
    config = {
        'id_regex': r'^processing repo (?P<value>.*)$',
        'id_justify': True,
        'id_width': max_length,
    }
    if progress:
        config['progress_bar'] = {
            'total': r'^processing total of (?P<value>\d+) commands for repo .*$',
            'count_regex': r'^executing command: (?P<value>.*)$',
            'progress_message': 'scanning of all branches complete'
        }
    mp4ansi = MP4ansi(function=scan_repo, process_data=process_data, config=config)
    mp4ansi.execute(raise_if_error=True)
    return get_results(process_data)


def match_repos(repos, include, exclude):
    """ match repos using include and exclude regex
    """
    logger.debug(f'matching repos using include {include} and exclude {exclude}')
    match_include = True
    match_exclude = False
    matched_repos = []
    for repo in repos:
        repo_name = repo['full_name']
        if include:
            match_include = re.match(include, repo_name)
        if exclude:
            match_exclude = re.match(exclude, repo_name)
        if match_include and not match_exclude:
            matched_repos.append(repo)
    return matched_repos


def display_results(results):
    """ print results
    """
    if any(results.values()):
        print('The following repos failed gitleaks scan:')
        for item in results:
            if results[item]:
                print(item)
    else:
        print('All branches in all repos passed gitleaks scan')


def get_user_repos(client):
    """ return repos for authenticated user
    """
    user = client.get('/user')['login']
    logger.debug(f'getting all repos for the authenticated user {user}')
    repos = client.get('/user/repos', _get='all', _attributes=['full_name', 'ssh_url'])
    return repos


def get_repos(client, filename, user):
    """ get repos for filename, user or org
    """
    if user:
        repos = get_user_repos(client)
    else:
        repos = get_file_repos(filename)
    return repos


def main():
    """ main function
    """
    args = get_parser().parse_args()
    configure_logging()
    client = get_client()
    repos = get_repos(client, args.filename, args.user)
    matched_repos = match_repos(repos, args.include, args.exclude)
    results = execute_scans(matched_repos, args.progress)
    display_results(results)


if __name__ == '__main__':
    main()
