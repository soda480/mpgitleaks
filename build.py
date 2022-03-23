#   -*- coding: utf-8 -*-
from pybuilder.core import use_plugin
from pybuilder.core import init
from pybuilder.core import Author

use_plugin('python.core')
use_plugin('python.unittest')
use_plugin('python.flake8')
use_plugin('python.coverage')
use_plugin('python.distutils')
use_plugin('pypi:pybuilder_radon')
use_plugin('pypi:pybuilder_bandit')
use_plugin('pypi:pybuilder_anybadge')

name = 'mpgitleaks'
authors = [Author('Emilio Reyes', 'soda480@gmail.com')]
summary = 'A Python script that wraps the gitleaks tool to enable scanning of multiple repositories in parallel'
url = 'https://github.com/soda480/mpgitleaks'
version = '0.1.9'
default_task = [
    'clean',
    'analyze',
    'publish',
    'radon',
    'bandit',
    'anybadge']
license = 'Apache License, Version 2.0'
description = summary


@init
def set_properties(project):
    project.set_property('unittest_module_glob', 'test_*.py')
    project.set_property('flake8_max_line_length', 120)
    project.set_property('flake8_verbose_output', True)
    project.set_property('flake8_break_build', True)
    project.set_property('flake8_include_scripts', True)
    project.set_property('flake8_include_test_sources', True)
    project.set_property('flake8_ignore', 'E501, F401')
    project.set_property('coverage_break_build', False)
    project.build_depends_on('mock')
    project.depends_on_requirements('requirements.txt')
    project.set_property('distutils_console_scripts', ['mpgitleaks = mpgitleaks.mpgitleaks:main'])
    project.set_property('radon_break_build_average_complexity_threshold', 4)
    project.set_property('radon_break_build_complexity_threshold', 10)
    project.set_property('bandit_break_build', True)
    project.set_property('bandit_skip_ids', 'B404,B603,B604')
    project.set_property('anybadge_use_shields', True)
    project.set_property('anybadge_exclude', 'coverage')
