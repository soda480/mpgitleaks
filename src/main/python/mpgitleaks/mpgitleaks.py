
import os
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
        help='file containing repositories to scan')
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


def get_file_repos(filename):
    """ return list of repos read from filename
    """
    if not os.access(filename, os.R_OK):
        raise ValueError(f"the default repos file '{filename}' cannot be read")
    with open(filename) as infile:
        return [line.strip() for line in infile.readlines()]


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
    repo_address = process_data['address']
    repo_owner = process_data['owner']
    repo_name = process_data['name']

    logger.debug(f'processing repo {repo_name}')

    client = get_client()
    branches = client.get(f'/repos/{repo_owner}/{repo_name}/branches', _get='all', _attributes=['name'])
    logger.debug(f'processing total of {len(branches)} branches for repo {repo_name}')

    dirs = create_directories()

    clone_dir = f"{dirs['clones']}/{repo_name}"
    shutil.rmtree(clone_dir, ignore_errors=True)
    execute_command(f'git clone {repo_address}', cwd=dirs['clones'])

    result = {}
    for branch in branches:
        branch_name = branch['name']
        logger.debug(f'processing branch {branch_name} for repo {repo_name}')
        execute_command(f'git checkout -b {branch_name} origin/{branch_name}', cwd=clone_dir)
        report = f"{dirs['reports']}/{repo_name}-{branch_name}.json"
        exit_code = execute_command(f'gitleaks --path=. --branch={branch_name} --report={report} --threads=10', cwd=clone_dir)
        result[f'{repo_owner}/{repo_name}:{branch_name}'] = False if exit_code == 0 else report
        logger.debug(f'processing of branch {branch_name} for repo {repo_name} is complete')

    logger.debug(f'processing of repo {repo_name} complete')
    return result


def get_results(process_data):
    """ return results
    """
    results = {}
    for process in process_data:
        results.update(process['result'])
    return results


def get_process_data(repos):
    """ return list of process data
    """
    process_data = []
    for address in repos:
        item = {
            'address': address,
            'owner': address.split(':')[1].split('/')[0],
            'name': address.split('/')[-1].replace('.git', '')
        }
        process_data.append(item)
    return process_data


def execute_scans(repos):
    """ return process data for multiprocessing
    """
    process_data = get_process_data(repos)
    max_length = max(len(item['name']) for item in process_data)
    config = {
        'id_regex': r'^processing repo (?P<value>.*)$',
        'id_justify': True,
        'id_width': max_length,
        # 'progress_bar': {
        #     'total': r'^processing total of (?P<value>\d+) branches$',
        #     'count_regex': r'^processing branch (?P<value>.*)$',
        #     'progress_message': 'scanning of all branches complete'
        # }
    }
    mp4ansi = MP4ansi(function=scan_repo, process_data=process_data, config=config)
    mp4ansi.execute(raise_if_error=True)
    return get_results(process_data)


def display_results(results):
    """ print results
    """
    if any(results.values()):
        print('the following repos failed gitleaks scan:')
        for item in results:
            if results[item]:
                print(item)
    else:
        print('all branches in all repos passed gitleaks scan')


def main():
    """ main function
    """
    args = get_parser().parse_args()
    configure_logging()
    get_client()
    repos = get_file_repos(args.filename)
    results = execute_scans(repos)
    display_results(results)


if __name__ == '__main__':
    main()
