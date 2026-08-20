import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(__file__, '..', '..')))

from beanbag_docutils.sphinx.ext.github import github_linkcode_resolve

import cryptozoology


project = 'Cryptozoology'
copyright = '2026, Beanbag, Inc.'
author = 'Beanbag, Inc.'
version = '.'.join([str(i) for i in cryptozoology.__version_info__[:2]])
release = cryptozoology.get_version_string()
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    'sphinx.ext.intersphinx',
    'sphinx.ext.linkcode',
    'sphinx.ext.napoleon',
    'sphinx.ext.todo',
    'beanbag_docutils.sphinx.ext.autodoc_utils',
    'beanbag_docutils.sphinx.ext.extlinks',
    'beanbag_docutils.sphinx.ext.http_role',
    'beanbag_docutils.sphinx.ext.ref_utils',
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

html_theme = 'furo'
html_static_path = ['_static']


intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
}

extlinks = {
    'pypi': ('https://pypi.org/project/%s/', '%s'),
}

autodoc_excludes = {
    '*': {
        '__annotations__',
        '__annotations_cache__',
        '__dict__',
        '__doc__',
        '__firstlineno__',
        '__module__',
        '__name__',
        '__orig_bases__',
        '__parameters__',
        '__qualname__',
        '__static_attributes__',
        '__supertype__',
        '__weakref__',
    },
}

add_function_parentheses = True
autosummary_generate = True


def linkcode_resolve(domain, info):
    major, minor, micro, tag, release_num, released = cryptozoology.VERSION
    is_final = (tag == 'final')

    if is_final or release_num > 0:
        branch = f'release-{major}'

        if released:
            branch += f'.{minor}'

            if micro:
                branch += f'.{micro}'

            if not is_final:
                branch += tag

                if release_num:
                    branch += str(release_num)
        else:
            branch += '.x'
    else:
        branch = 'master'

    return github_linkcode_resolve(
        domain=domain,
        info=info,
        allowed_module_names=['cryptozoology'],
        github_org_id='beanbaginc',
        github_repo_id='cryptozoology',
        branch=branch,
    )
