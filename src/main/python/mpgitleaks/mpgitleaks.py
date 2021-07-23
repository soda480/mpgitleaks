#   -*- coding: utf-8 -*-
import os
import re
import sys
import csv
import json
import shutil
import logging
import argparse
import subprocess
from queue import Empty
from pathlib import Path
from multiprocessing import Queue

from colorama import Style
from colorama import Fore
from mp4ansi import MP4ansi
from github3api import GitHubAPI

logger = logging.getLogger(__name__)

HOME = '/opt/mpgitleaks'
MAX_PROCESSES = 35


class ColoredFormatter(logging.Formatter):
    """  colored formatter
    """
    level_format = {
        logging.DEBUG: Style.DIM + "%(levelname)s" + Style.RESET_ALL,
        logging.INFO: Style.BRIGHT + "%(levelname)s" + Style.RESET_ALL,
        logging.WARNING: Style.BRIGHT + Fore.YELLOW + "%(levelname)s" + Style.RESET_ALL,
        logging.ERROR: Style.BRIGHT + Fore.RED + "%(levelname)s" + Style.RESET_ALL,
        logging.CRITICAL: Style.BRIGHT + Fore.RED + "%(levelname)s" + Style.RESET_ALL,
    }

    def format(self, record):
        level_format = self.level_format.get(record.levelno)
        formatter = logging.Formatter("[" + level_format + "] %(message)s")
        return formatter.format(record)


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
        help='scan repos contained in the specified file')
    parser.add_argument(
        '--user',
        dest='user',
        action='store_true',
        help='scan repos for the authenticated GitHub user where user is owner or collaborator')
    parser.add_argument(
        '--org',
        dest='org',
        type=str,
        default=None,
        required=False,
        help='scan repos for the specified GitHub organization')
    parser.add_argument(
        '--exclude',
        dest='exclude',
        type=str,
        default='',
        required=False,
        help='a regex to match name of repos to exclude from scanning')
    parser.add_argument(
        '--include',
        dest='include',
        type=str,
        default='',
        required=False,
        help='a regex to match name of repos to include in scanning')
    parser.add_argument(
        '--debug',
        dest='debug',
        action='store_true',
        help='log debug messages to a log file')
    return parser


def log_message(message, info=False):
    """ log message
        mitigate lazy formatting
    """
    if info:
        logger.info(message)
    else:
        logger.debug(message)


def configure_logging(create):
    """ configure logging and create logfile if specified
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    if create:
        name = os.path.basename(sys.argv[0])
        file_handler = logging.FileHandler(f'{name}.log')
        file_formatter = logging.Formatter("%(asctime)s %(processName)s [%(funcName)s] %(levelname)s %(message)s")
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)


def add_stream_handler(stream_handler=None):
    """ add stream handler to logging
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    if not stream_handler:
        stream_handler = logging.StreamHandler()
        stream_formatter = ColoredFormatter()
        stream_handler.setFormatter(stream_formatter)
        stream_handler.setLevel(logging.INFO)
    root_logger.addHandler(stream_handler)
    return stream_handler


def remove_stream_handler(stream_handler):
    """ remove stream handler from logging
    """
    root_logger = logging.getLogger()
    root_logger.removeHandler(stream_handler)


def get_credentials():
    """ return tuple of username, password from environment
    """
    username = os.getenv('USERNAME')
    if not username:
        raise ValueError('USERNAME environment variable must be set')
    password = os.getenv('PASSWORD')
    if not password:
        raise ValueError('PASSWORD environment variable must be set')
    return username, password


def get_client():
    """ return instance of GitHubAPI client
    """
    _, password = get_credentials()
    return GitHubAPI(bearer_token=password, hostname=os.getenv('GH_BASE_URL'))


def redact(str_to_redact, items_to_redact):
    """ return str_to_redact with items redacted
    """
    if items_to_redact:
        for item_to_redact in items_to_redact:
            str_to_redact = str_to_redact.replace(item_to_redact, '***')
    return str_to_redact


def execute_command(command, items_to_redact=None, **kwargs):
    """ execute command
    """
    command_split = command.split(' ')
    redacted_command = redact(command, items_to_redact)
    log_message(f'executing command: {redacted_command}')
    process = subprocess.run(command_split, capture_output=True, text=True, **kwargs)
    log_message(f"executed command: {redacted_command}' returncode: {process.returncode}")
    if process.stdout:
        log_message(f'stdout:\n{process.stdout}')
    if process.stderr:
        log_message(f'stderr:\n{process.stderr}')
    return process


def get_repo_data(clone_urls):
    """ return list of repo data from clone_urls
    """
    repos = []
    for clone_url in clone_urls:
        owner = clone_url.split('/')[3]
        name = clone_url.split('/')[-1].replace('.git', '')
        item = {
            'clone_url': clone_url,
            'full_name': f'{owner}/{name}'
        }
        repos.append(item)
    return repos


def create_dirs():
    """ create and return required directories
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


def get_leak_count(filename):
    """ return number of items read in from filename
    """
    with open(filename) as infile:
        data = json.load(infile)
    return len(data)


def get_scan_result(branch_name, exit_code, report):
    """ return dictionary representing scan result
    """
    result = {
        'branch': branch_name,
        'leaks': False,
        'leak_count': 0,
        'report': 'NA'
    }
    if exit_code != 0:
        result['leaks'] = True
        result['leak_count'] = get_leak_count(report)
        result['report'] = report.replace(os.getenv('PWD', HOME), '.')
    return result


def get_branches(clone_dir):
    """ return list of branches from clone_dir
        clone_dir should be a git repository
    """
    logger.debug(f'getting branches from: {clone_dir}')
    process = execute_command('git branch -a', cwd=clone_dir)
    if process.returncode != 0:
        raise Exception('unable to get branches')
    branches = []
    stdout_lines = process.stdout.strip().split('\n')
    for line in stdout_lines:
        regex = '^.*origin/(?P<name>.*)$'
        match = re.match(regex, line)
        if match:
            branch_name = match.group('name')
            if branch_name not in branches:
                branches.append(branch_name)
    return branches


def scan_repo(process_data, *args):
    """ execute gitleaks scan on all branches of repo
    """
    repo_clone_url = process_data['clone_url']
    repo_full_name = process_data['full_name']
    repo_name = repo_full_name.replace('/', '|')

    username, password = get_credentials()

    log_message(f'scanning item {repo_full_name}')

    dirs = create_dirs()
    clone_dir = f"{dirs['clones']}/{repo_name}"
    shutil.rmtree(clone_dir, ignore_errors=True)
    repo_clone_url = repo_clone_url.replace('https://', f'https://{username}:{password}@')
    execute_command(f'git clone {repo_clone_url} {repo_name}', items_to_redact=[password], cwd=dirs['clones'])

    branches = get_branches(clone_dir)
    logger.debug(branches)
    log_message(f'executing {len(branches) * 2} commands to scan repo {repo_full_name}')

    results = []
    for branch_name in branches:
        branch_full_name = f"{repo_full_name}@{branch_name}"
        safe_branch_full_name = branch_full_name.replace('/', '|')
        log_message(f'scanning branch {branch_full_name}')
        execute_command(f'git checkout -b {branch_name} origin/{branch_name}', cwd=clone_dir)
        report = f"{dirs['reports']}/{safe_branch_full_name}.json"
        process = execute_command(f'gitleaks --path=. --branch={branch_name} --report={report} --threads=10', cwd=clone_dir)
        results.append(get_scan_result(branch_full_name, process.returncode, report))
        log_message(f'scanning of branch {branch_full_name} complete')

    log_message(f'scanning of repo {repo_full_name} complete')
    return results


def scan_repo_queue(process_data, *args):
    """ execute gitleaks scan on all branches of repo pulled from queue
    """
    repo_queue = process_data['item_queue']
    queue_size = process_data['queue_size']
    username, password = get_credentials()
    dirs = create_dirs()
    zfill = len(str(queue_size))
    results = []
    repo_count = 0
    while True:
        try:
            repo = repo_queue.get(timeout=6)
            # reset progress bar for next repo
            log_message('RESET')

            repo_clone_url = repo['clone_url']
            repo_full_name = repo['full_name']
            safe_repo_full_name = repo_full_name.replace('/', '|')

            log_message(f'scanning item [{str(repo_count).zfill(zfill)}] {repo_full_name}')

            clone_dir = f"{dirs['clones']}/{safe_repo_full_name}"
            shutil.rmtree(clone_dir, ignore_errors=True)
            repo_clone_url = repo_clone_url.replace('https://', f'https://{username}:{password}@')
            execute_command(f'git clone {repo_clone_url} {safe_repo_full_name}', items_to_redact=[password], cwd=dirs['clones'])

            branches = get_branches(clone_dir)
            log_message(f'executing {len(branches) * 2} commands to scan repo {repo_full_name}')

            for branch_name in branches:
                branch_full_name = f"{repo_full_name}@{branch_name}"
                safe_branch_full_name = branch_full_name.replace('/', '|')
                log_message(f'scanning branch {branch_full_name}')
                execute_command(f'git checkout -b {branch_name} origin/{branch_name}', cwd=clone_dir)
                report = f"{dirs['reports']}/{safe_branch_full_name}.json"
                process = execute_command(f'gitleaks --path=. --branch={branch_name} --report={report} --threads=10', cwd=clone_dir)
                results.append(get_scan_result(branch_full_name, process.returncode, report))
                log_message(f'scanning of branch {branch_full_name} complete')

            log_message(f'scanning of repo {repo_full_name} complete')
            repo_count += 1
            log_message(f'scanning item [{str(repo_count).zfill(zfill)}]')

        except Empty:
            log_message('repo queue is empty')
            break
    log_message(f'scanning complete - scanned {str(repo_count).zfill(zfill)} repos')
    return results


def get_results(process_data):
    """ return results from process data
    """
    results = []
    for process in process_data:
        results.extend(process['result'])
    return results


def get_process_data_queue(items):
    """ get process data for queue processing
    """
    item_queue = Queue()
    for item in items:
        item_queue.put(item)
    process_data = []
    for _ in range(MAX_PROCESSES):
        process_data.append({
            'item_queue': item_queue,
            'queue_size': item_queue.qsize()
        })
    return process_data


def execute_scans(items):
    """ execute scans for repoos using multiprocessing
    """
    if not items:
        raise ValueError('no reopos to scan')

    arguments = {}
    if len(items) <= MAX_PROCESSES:
        arguments['function'] = scan_repo
        arguments['process_data'] = items
    else:
        arguments['function'] = scan_repo_queue
        arguments['process_data'] = get_process_data_queue(items)

    arguments['config'] = {
        'id_regex': r'^scanning item (?P<value>.*)$',
        'progress_bar': {
            'total': r'^executing (?P<value>\d+) commands to scan .*$',
            'count_regex': r'^executed command: (?P<value>.*)$',
            'max_digits': 2
        }
    }
    mp4ansi = MP4ansi(**arguments)
    mp4ansi.execute(raise_if_error=True)
    return get_results(mp4ansi.process_data)


def get_authenticated_user(client):
    """ return the name of the authenticated user
    """
    return client.get('/user')['login']


def get_file_repos(filename):
    """ return repos read from filename
    """
    log_message(f"retrieving repos from file '{filename}'", info=True)
    if not os.access(filename, os.R_OK):
        raise ValueError(f"repos file '{filename}' cannot be read")
    with open(filename) as infile:
        clone_urls = [line.strip() for line in infile.readlines()]
    repos = get_repo_data(clone_urls)
    log_message(f"{len(repos)} repos were retrieved from file '{filename}'", info=True)
    return repos


def get_user_repos():
    """ return repos for authenticated user
    """
    client = get_client()
    username = get_authenticated_user(client)
    log_message(f"retrieving repos from authenticated user '{username}'", info=True)
    repos = client.get('/user/repos?affiliation=owner,collaborator', _get='all', _attributes=['full_name', 'clone_url'])
    log_message(f"{len(repos)} repos were retrieved from authenticated user '{username}'", info=True)
    return repos


def get_org_repos(org):
    """ return repos for organization
    """
    client = get_client()
    log_message(f"retrieving repos from organization '{org}'", info=True)
    repos = client.get(f'/orgs/{org}/repos', _get='all', _attributes=['full_name', 'clone_url'])
    log_message(f"{len(repos)} repos were retrieved from organization '{org}'", info=True)
    return repos


def get_repos(filename, user, org):
    """ get repos for filename, user or org
    """
    if user:
        repos = get_user_repos()
    elif org:
        repos = get_org_repos(org)
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


def get_matched(items, include, exclude, item_type):
    """ return matched items using include and exclude regex
    """
    log_message(f"filtering {item_type} using include '{include}' and exclude '{exclude}' criteria")
    matched = []
    for item in items:
        match_include, match_exclude = match_criteria(item['full_name'], include, exclude)
        if match_include and not match_exclude:
            matched.append(item)
    log_message(f"{len(matched)} {item_type} remain after applying inclusion/exclusion filters", info=True)
    return matched


def match_items(items, include, exclude, item_type):
    """ match items using include and exclude regex
    """
    if not include and not exclude:
        return items
    return get_matched(items, include, exclude, item_type)


def write_csv(data, filename):
    """ write data to csv file
    """
    headers = data[0].keys()
    with open(filename, 'w') as outfile:
        writer = csv.DictWriter(outfile, headers)
        writer.writeheader()
        writer.writerows(data)


def check_results(results):
    """ check results and write summary
    """
    name = os.path.basename(sys.argv[0])
    filename = f'{name}.csv'
    if any(result['leaks'] for result in results):
        log_message('gitleaks DID detect hardcoded secrets')
        print(f"{Style.BRIGHT + Fore.RED}GITLEAKS SCAN NOT OK - SECRETS DETECTED{Style.RESET_ALL}")
    else:
        log_message('gitleaks DID NOT detect hardcoded secrets')
        print(f"{Style.BRIGHT + Fore.GREEN}GITLEAKS SCAN OK{Style.RESET_ALL}")
    write_csv(results, filename)
    log_message(f"{len(results)} branches scanned - summary report written to '{filename}'", info=True)


def main():
    """ main function
    """
    args = get_parser().parse_args()
    configure_logging(args.debug)
    stream_handler = add_stream_handler()

    try:
        get_credentials()
        repos = get_repos(args.filename, args.user, args.org)
        matched_repos = match_items(repos, args.include, args.exclude, 'repos')
        remove_stream_handler(stream_handler)
        results = execute_scans(matched_repos)
        add_stream_handler(stream_handler=stream_handler)
        check_results(results)

    except Exception as exception:
        add_stream_handler(stream_handler=stream_handler)
        logger.error(exception)
        sys.exit(-1)


if __name__ == '__main__':
    main()
