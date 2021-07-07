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

from mp4ansi import MP4ansi
from github3api import GitHubAPI

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
        help='process repos contained in the specified file')
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
        help='process repos for the specified organization')
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
        '--progress',
        dest='progress',
        action='store_true',
        help='display progress bar for each process')
    parser.add_argument(
        '--log',
        dest='log',
        action='store_true',
        help='log messages to a log file')
    parser.add_argument(
        '--branches',
        dest='branches',
        action='store_true',
        help='set process affinity at repo branch level')
    return parser


def configure_logging(create):
    """ configure logging
    """
    if not create:
        return
    name = os.path.basename(sys.argv[0])
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    file_handler = logging.FileHandler(f'{name}.log')
    file_formatter = logging.Formatter("%(asctime)s %(processName)s [%(funcName)s] %(levelname)s %(message)s")
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)


def echo(message):
    """ print and log message
    """
    logger.debug(message)
    print(message)


def get_client():
    """ return instance of GitHubAPI client
    """
    if not os.getenv('GH_TOKEN_PSW'):
        raise ValueError('GH_TOKEN_PSW environment variable must be set to token')
    return GitHubAPI.get_client()


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
    logger.debug(f'executing command: {redacted_command}')
    process = subprocess.run(command_split, capture_output=True, text=True, **kwargs)
    logger.debug(f'executed command: {redacted_command}')
    logger.debug(f'returncode: {process.returncode}')
    if process.stdout:
        logger.debug(f'stdout:\n{process.stdout}')
    if process.stderr:
        logger.debug(f'stderr:\n{process.stderr}')
    return process.returncode


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


def scan_repo(process_data, shared_data):
    """ execute gitleaks scan on all branches of repo
    """
    repo_clone_url = process_data['clone_url']
    repo_full_name = process_data['full_name']
    username = shared_data['username']
    repo_name = repo_full_name.replace('/', '|')

    client = get_client()
    branches = client.get(f'/repos/{repo_full_name}/branches', _get='all', _attributes=['name'])
    logger.debug(f'executing {len(branches) * 2 + 2} commands to scan repo {repo_full_name}')

    logger.debug(f'scanning item {repo_full_name}')
    logger.debug('executed command: setup')

    dirs = create_dirs()
    clone_dir = f"{dirs['clones']}/{repo_name}"
    shutil.rmtree(clone_dir, ignore_errors=True)
    repo_clone_url = repo_clone_url.replace('https://', f'https://{username}:{client.bearer_token}@')

    execute_command(f'git clone {repo_clone_url} {repo_name}', items_to_redact=[client.bearer_token], cwd=dirs['clones'])

    results = []
    for branch in branches:
        branch_name = branch['name']
        branch_full_name = f"{repo_full_name}@{branch_name}"
        safe_branch_full_name = branch_full_name.replace('/', '|')
        logger.debug(f'scanning branch {branch_full_name}')
        execute_command(f'git checkout -b {branch_name} origin/{branch_name}', cwd=clone_dir)
        report = f"{dirs['reports']}/{safe_branch_full_name}.json"
        exit_code = execute_command(f'gitleaks --path=. --branch={branch_name} --report={report} --threads=10', cwd=clone_dir)
        results.append(get_scan_result(branch_full_name, exit_code, report))
        logger.debug(f'scanning of branch {branch_full_name} complete')

    logger.debug(f'scanning of repo {repo_full_name} complete')
    return results


def scan_branch(process_data, shared_data):
    """ execute gitleaks scan on all branches of repo
    """
    results = []
    username = shared_data['username']
    repo_clone_url = process_data['clone_url']
    repo_full_name = process_data['full_name']
    branch_name = process_data['branch_name']
    branch_full_name = f"{repo_full_name}@{branch_name}"
    safe_branch_full_name = branch_full_name.replace('/', '|')
    bearer_token = os.getenv('GH_TOKEN_PSW')

    logger.debug(f'scanning item {branch_full_name}')
    logger.debug(f'executing 2 commands to scan branch {branch_full_name}')

    dirs = create_dirs()
    # clone repo branch
    clone_dir = f"{dirs['clones']}/{safe_branch_full_name}"
    shutil.rmtree(clone_dir, ignore_errors=True)
    repo_clone_url = repo_clone_url.replace('https://', f'https://{username}:{bearer_token}@')
    execute_command(f'git clone --single-branch --branch {branch_name} {repo_clone_url} {safe_branch_full_name}', items_to_redact=[bearer_token], cwd=dirs['clones'])

    # execute gitleaks
    report = f"{dirs['reports']}/{safe_branch_full_name}.json"
    exit_code = execute_command(f'gitleaks --path=. --branch={branch_name} --report={report} --threads=10', cwd=clone_dir)
    results.append(get_scan_result(branch_full_name, exit_code, report))
    logger.debug(f'scanning of branch {branch_full_name} complete')
    return results


def scan_repo_queue(process_data, shared_data):
    """ execute gitleaks scan on all branches of repo pulled from queue
    """
    offset = process_data['offset']
    repo_queue = process_data['item_queue']
    queue_size = process_data['queue_size']
    username = shared_data['username']
    dirs = create_dirs()
    client = get_client()
    zfill = len(str(queue_size))
    results = []
    repo_count = 0
    while True:
        try:
            repo = repo_queue.get(timeout=6)
            # reset progress bar for next repo
            logger.debug('RESET')

            repo_clone_url = repo['clone_url']
            repo_full_name = repo['full_name']
            safe_repo_full_name = repo_full_name.replace('/', '|')

            logger.debug(f'scanning item [{str(repo_count).zfill(zfill)}] {repo_full_name}')

            branches = client.get(f'/repos/{repo_full_name}/branches', _get='all', _attributes=['name'])
            logger.debug(f'executing {len(branches) * 2 + 1} commands to scan repo {repo_full_name}')

            clone_dir = f"{dirs['clones']}/{safe_repo_full_name}"
            shutil.rmtree(clone_dir, ignore_errors=True)
            repo_clone_url = repo_clone_url.replace('https://', f'https://{username}:{client.bearer_token}@')
            execute_command(f'git clone {repo_clone_url} {safe_repo_full_name}', items_to_redact=[client.bearer_token], cwd=dirs['clones'])

            for branch in branches:
                branch_name = branch['name']
                branch_full_name = f"{repo_full_name}@{branch_name}"
                safe_branch_full_name = branch_full_name.replace('/', '|')
                logger.debug(f'scanning branch {branch_full_name}')
                execute_command(f'git checkout -b {branch_name} origin/{branch_name}', cwd=clone_dir)
                report = f"{dirs['reports']}/{safe_branch_full_name}.json"
                exit_code = execute_command(f'gitleaks --path=. --branch={branch_name} --report={report} --threads=10', cwd=clone_dir)
                results.append(get_scan_result(branch_full_name, exit_code, report))
                logger.debug(f'scanning of branch {branch_full_name} complete')

            logger.debug(f'scanning of repo {repo_full_name} complete')
            repo_count += 1
            logger.debug(f'scanning item [{str(repo_count).zfill(zfill)}]')

        except Empty:
            logger.debug('repo queue is empty')
            break
    logger.debug(f'scanning complete - scanned {str(repo_count).zfill(zfill)} repos')
    return results


def scan_branch_queue(process_data, shared_data):
    """ execute gitleaks scan on single branch of repo pulled from queue
    """
    offset = process_data['offset']
    branch_queue = process_data['item_queue']
    queue_size = process_data['queue_size']
    username = shared_data['username']
    dirs = create_dirs()
    client = get_client()
    zfill = len(str(queue_size))
    results = []
    branch_count = 0
    while True:
        try:
            branch = branch_queue.get(timeout=6)
            # reset progress bar for next item
            logger.debug('RESET')

            repo_clone_url = branch['clone_url']
            repo_full_name = branch['full_name']
            branch_name = branch['branch_name']

            branch_full_name = f"{repo_full_name}@{branch_name}"
            safe_branch_full_name = branch_full_name.replace('/', '|')

            logger.debug(f'scanning item [{str(branch_count).zfill(zfill)}] {branch_full_name}')
            logger.debug(f'executing 2 commands to scan branch {branch_full_name}')

            clone_dir = f"{dirs['clones']}/{safe_branch_full_name}"
            shutil.rmtree(clone_dir, ignore_errors=True)
            repo_clone_url = repo_clone_url.replace('https://', f'https://{username}:{client.bearer_token}@')
            execute_command(f'git clone --single-branch --branch {branch_name} {repo_clone_url} {safe_branch_full_name}', items_to_redact=[client.bearer_token], cwd=dirs['clones'])

            report = f"{dirs['reports']}/{safe_branch_full_name}.json"
            exit_code = execute_command(f'gitleaks --path=. --branch={branch_name} --report={report} --threads=10', cwd=clone_dir)
            results.append(get_scan_result(branch_full_name, exit_code, report))

            logger.debug(f'scanning of branch {branch_full_name} is complete')
            branch_count += 1
            logger.debug(f'scanning item [{str(branch_count).zfill(zfill)}]')

        except Empty:
            logger.debug('repo branch queue is empty')
            break
    logger.debug(f'scanning complete - scanned {str(branch_count).zfill(zfill)} branches')
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
    for offset in range(MAX_PROCESSES):
        process_data.append({
            'offset': str(offset).zfill(len(str(MAX_PROCESSES))),
            'item_queue': item_queue,
            'queue_size': item_queue.qsize()
        })
    return process_data


def get_arguments_for_queued_execution(items, branches):
    """ return mp4ansi arguments for queued execution
    """
    arguments = {}
    function = scan_repo_queue
    if branches:
        function = scan_branch_queue
    config = {
        'id_regex': r'^scanning item (?P<value>.*)$',
        'text_regex': r'scanning|executing'
    }
    process_data = get_process_data_queue(items)
    arguments['function'] = function
    arguments['process_data'] = process_data
    arguments['config'] = config
    return arguments


def get_arguments_for_execution(items, branches):
    """ return mp4ansi arguments for non queued execution
    """
    arguments = {}
    function = scan_repo
    if branches:
        function = scan_branch
    process_data = items
    config = {
        'id_regex': r'^scanning item (?P<value>.*)$',
        'text_regex': r'scanning|executing'
    }
    arguments['function'] = function
    arguments['process_data'] = process_data
    arguments['config'] = config
    return arguments


def execute_scans(items, progress, username, branches):
    """ execute scans for repoos using multiprocessing
    """
    if not items:
        raise ValueError('no reopos or branches to scan')

    if len(items) <= MAX_PROCESSES:
        arguments = get_arguments_for_execution(items, branches)
    else:
        arguments = get_arguments_for_queued_execution(items, branches)

    arguments['shared_data'] = {
        'username': username
    }

    if progress:
        arguments['config']['progress_bar'] = {
            'total': r'^executing (?P<value>\d+) commands to scan .*$',
            'count_regex': r'^executed command: (?P<value>.*)$',
            'max_digits': 2
            # 'progress_message': 'Processing complete'
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
    echo(f"Getting repos from file '{filename}' ...")
    if not os.access(filename, os.R_OK):
        raise ValueError(f"the default repos file '{filename}' cannot be read")
    with open(filename) as infile:
        clone_urls = [line.strip() for line in infile.readlines()]
    repos = get_repo_data(clone_urls)
    echo(f"A total of {len(repos)} repos were read in from '{filename}'")
    return repos


def get_user_repos(client, username):
    """ return repos for authenticated user
    """
    echo(f"Getting repos for the authenticated user '{username}' ...")
    repos = client.get('/user/repos', _get='all', _attributes=['full_name', 'clone_url'])
    echo(f"A total of {len(repos)} repos were retrieved from authenticated user '{username}'")
    return repos


def get_org_repos(client, org):
    """ return repos for organization
    """
    echo(f"Getting repos for org: '{org}' ...")
    repos = client.get(f'/orgs/{org}/repos', _get='all', _attributes=['full_name', 'clone_url'])
    echo(f"A total of {len(repos)} repos were retrieved from organization '{org}'")
    return repos


def get_repos(client, filename, user, org, username):
    """ get repos for filename, user or org
    """
    if user:
        repos = get_user_repos(client, username)
    elif org:
        repos = get_org_repos(client, org)
    else:
        repos = get_file_repos(filename)
    return repos


def get_branches(client, repos):
    """ returl list of branches for repos
    """
    echo(f"Getting branches for {len(repos)} repos ...")
    branches = []
    for repo in repos:
        repo_full_name = repo['full_name']
        repo_branches = client.get(f'/repos/{repo_full_name}/branches', _get='all', _attributes=['name'])
        for branch in repo_branches:
            item = {}
            item.update(repo)
            item['branch_name'] = branch['name']
            item['full_name'] = f"{item['full_name']}:{item['branch_name']}"
            branches.append(item)
    echo(f"A total of {len(branches)} branches were retrieved from {len(repos)} repos")
    return branches


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
    logger.debug(f'filtering {item_type} using include {include} and exclude {exclude} criteria')
    matched = []
    for item in items:
        match_include, match_exclude = match_criteria(item['full_name'], include, exclude)
        if match_include and not match_exclude:
            matched.append(item)
    echo(f"A total of {len(matched)} {item_type} were filtered using the inclusion/exclusion criteria")
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
        echo('Leaks were found')
    else:
        echo('No leaks were found')
    write_csv(results, filename)
    echo(f'A summary report has been written to: {filename}')


def main():
    """ main function
    """
    args = get_parser().parse_args()
    configure_logging(args.log)

    try:
        client = get_client()
        username = get_authenticated_user(client)

        repos = get_repos(client, args.filename, args.user, args.org, username)
        matched_repos = match_items(repos, args.include, args.exclude, 'repos')
        if args.branches:
            branches = get_branches(client, matched_repos)
            matched_items = match_items(branches, args.include, args.exclude, 'branches')
        else:
            matched_items = matched_repos

        results = execute_scans(matched_items, args.progress, username, args.branches)
        check_results(results)

    except Exception as exception:
        logger.error(exception)
        print(f'Error: {exception}')
        sys.exit(-1)


if __name__ == '__main__':
    main()
