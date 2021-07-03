
import os
import logging
import subprocess
import argparse
# from time import sleep

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
    if kwargs.get('shell') and kwargs['shell']:
        command_split = command
    else:
        command_split = command.split(' ')
    logger.debug(f'executing command: {command}')
    process = subprocess.run(command_split, capture_output=True, text=True, **kwargs)
    logger.debug(f'returncode: {process.returncode}')
    if process.stdout:
        logger.debug(f'stdout:\n{process.stdout}')
    if process.stderr:
        logger.debug(f'stderr:\n{process.stderr}')
    return process.returncode


def get_repos(filename):
    """ return list of repos read from filename
    """
    if not os.access(filename, os.R_OK):
        raise ValueError(f"the default repos file '{filename}' cannot be read")
    with open(filename) as infile:
        return infile.readlines()


def scan_repo(process_data, *args):
    """ scan repo
    """
    result = {}
    client = get_client()
    address = process_data['address']
    repo = process_data['repo']
    owner = process_data['owner']
    logger.debug(f'processing repo {repo}')

    scans_dir = f"{os.getenv('PWD', HOME)}/scans"
    clones_dir = f'{scans_dir}/clones'
    reports_dir = f'{scans_dir}/reports'
    clone_dir = f'{clones_dir}/{repo}'
    execute_command(f'mkdir -p {scans_dir}', shell=True)
    execute_command(f'mkdir -p {clones_dir}', shell=True)
    execute_command(f'mkdir -p {reports_dir}', shell=True)
    execute_command(f'rm -rf {clone_dir}', shell=True)
    execute_command(f'git clone {address}', cwd=clones_dir)
    branches = client.get(f'/repos/{owner}/{repo}/branches', _get='all', _attributes=['name'])
    logger.debug(f'processing total of {len(branches)} branches')
    for branch in branches:
        branch = branch['name']
        logger.debug(f'processing branch {branch}')
        execute_command(f'/usr/bin/git checkout -b {branch} origin/{branch}', cwd=clone_dir)
        exit_code = execute_command(f'/usr/bin/gitleaks --path=. --branch={branch} --report={reports_dir}/{repo}-{branch}.json --threads=10', cwd=clone_dir)
        result[f'{owner}/{repo}:{branch}'] = False if exit_code == 0 else True
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
        address = address.strip()
        item = {
            'address': address,
            'owner': address.split(':')[1].split('/')[0],
            'repo': address.split('/')[-1].replace('.git', '')
        }
        process_data.append(item)
    return process_data


def execute_scans(repos):
    """ return process data for multiprocessing
    """
    process_data = get_process_data(repos)
    max_length = max(len(item['repo']) for item in process_data)
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
    repos = get_repos(args.filename)
    results = execute_scans(repos)
    display_results(results)


if __name__ == '__main__':
    main()
