# MIT License
#
# Copyright (C) 2023 Nectar Technologies
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
#
####################################################################################################
# Description:
#   This script should be included in the .bashrc file of the user that will be running the
#   test automation or developing on the project.
#   Example:
#     At the end of the ~/.bashrc file (or ~/.bash_profile if using a mac), add this line:
#       . /path/to/this/file/bash_profile_include.sh

# Each repo must conform to this format: <repo-service>/<org>/<repo-name>
# Examples:
#   github.com/github.com/NectarTechnologies/code_samples/health_check
PROJECT_FULL_NAME__HEALTH_CHECK="github.com/NectarTechnologies/code_samples/health_check"
REPO_NAME__HEALTH_CHECK=$(echo "${PROJECT_FULL_NAME__HEALTH_CHECK}" |awk -F '/' '{print $3}')
PROJECT_NAME__HEALTH_CHECK=$(echo "${PROJECT_FULL_NAME__HEALTH_CHECK}" |awk -F '/' '{print $NF}')

# NOTE: This function name MUST always contain the "short nane" of the repo that is being worked on.
#       This is because the function generates repo specific environment variables.
function set_working_vars__health_check() {
    # Version of Python to use
    PY_VER="3.11"

    # Path should be relative to the root directory of the project.
    REQS_FILE_NAME="requirements.txt"
    INSTALL_ALL_REQS_SCRIPT="setup/install_all_requirements.sh"
    WORKSPACE_BASE_DIR="${HOME}/workspace"
    REPO_SRC="${WORKSPACE_BASE_DIR}/src/${PROJECT_FULL_NAME__HEALTH_CHECK}"
    REPO_VENV="${WORKSPACE_BASE_DIR}/venv/${PROJECT_FULL_NAME__HEALTH_CHECK}_venv"

    if [[ "${TEST_OUTPUT_PATH}" == "" ]]; then
        export TEST_OUTPUT_PATH="${WORKSPACE_BASE_DIR}/test-output/${PROJECT_FULL_NAME__HEALTH_CHECK}"
    fi
}

function what_os() {
    if [[ "$(uname)" == "Darwin" ]]; then
        echo "mac"
    else
        echo "linux"
    fi
}

function set_venv_vars() {
    if [[ -f ${REPO_SRC}/.env ]]; then
        while read LINE; do
            export "${LINE}"
        done < ${REPO_SRC}/.env
    fi
}

function unset_venv_vars() {
    if [[ -f ${REPO_SRC}/.env ]]; then
        while read LINE; do
            VAR=$(echo "${LINE}" |awk -F '=' '{print $1}' |grep -vE '^PATH')
            unset ${VAR}
        done < ${REPO_SRC}/.env
    fi
    unset TEST_OUTPUT_PATH
    unset REPO_SRC
    unset REPO_VENV
}

# NOTE: This function name MUST always contain the "short nane" of the repo that is being worked on.
#       This is because the function generates repo specific environment variables.
function activate_repo_venv__health_check() {
    set_working_vars__health_check
    if [[ ! -f "${REPO_VENV}/bin/activate" ]]; then
        echo "Could not find virtual environment at: \"${REPO_VENV}\""
    else
        . ${REPO_VENV}/bin/activate
        pushd ${REPO_SRC} 1>/dev/null 2>&1
        set_venv_vars ${REPO_SRC}
    fi
}

# NOTE: This function name MUST always contain the "short nane" of the repo that is being worked on.
#       This is because the function generates repo specific environment variables.
function init_and_activate_repo__health_check() {
    set_working_vars__health_check
    echo ""
    echo "--------------------------------------------------------------------"
    echo "Checking for project directory: \"${REPO_SRC}\""
    if [[ ! -d "${REPO_SRC}" ]]; then
        echo ""
        echo "Cannot find project directory: \"${REPO_SRC}\""
        echo "Perhaps repo is not yet cloned?"
        echo ""
        exit 1
    else
        echo "Found project directory: \"${REPO_SRC}\""
    fi

    echo ""
    echo "--------------------------------------------------------------------"
    echo "Checking for Python virtual environment directory: \"${REPO_VENV}\""
    if [[ ! -d "${REPO_VENV}" ]]; then
        echo "Creating directory: \"${REPO_VENV}\""
        mkdir -p "${REPO_VENV}"
        echo "Creating Python venv: \"${REPO_VENV}\""
        if [[ "$(what_os)" == "mac" ]]; then
            # For some reason, on mac, the --copies flag is not working.
            # So just create the venv without --copies which will do everything we need
            # but "python", "python3", and "python3.x" will all be symlinks to the host's
            # binaries.
            echo "Command: \"python${PY_VER} -m venv ${REPO_VENV}\""
            python${PY_VER} -m venv ${REPO_VENV}
        else
            # Linux
            echo "Command: \"python${PY_VER} -m venv --copies ${REPO_VENV}\""
            python${PY_VER} -m venv --copies ${REPO_VENV}
        fi

        if [[ "$?" -ne "0" ]]; then
            echo "Could not create virtual environment at: \"${REPO_VENV}\""
        fi
    else
        echo "Found Python virtual environment directory: \"${REPO_VENV}\""
    fi

    echo ""
    echo "--------------------------------------------------------------------"
    echo "Checking for test output directory: \"${TEST_OUTPUT_PATH}\""
    if [[ ! -d "${TEST_OUTPUT_PATH}" ]]; then
        echo "Creating test-output directory: \"${TEST_OUTPUT_PATH}\""
        mkdir -p "${TEST_OUTPUT_PATH}"
    else
        echo "Found test output directory: \"${TEST_OUTPUT_PATH}\""
    fi

    echo ""
    echo "--------------------------------------------------------------------"
    echo "Activating virtual environment"
    activate_repo_venv__health_check

    if [[ ! -f "${REPO_VENV}/bin/activate" ]]; then
        echo "Error: Cannot install project requirements because virtual environment could not be found."
    else
        echo ""
        echo "--------------------------------------------------------------------"
        echo "Installing/upgrading pip"
        pip install --upgrade pip

        echo ""
        echo "--------------------------------------------------------------------"
        _SRC_DIR=${REPO_SRC}
        echo "Checking for \"${_SRC_DIR}/${INSTALL_ALL_REQS_SCRIPT}\""
        pushd ${_SRC_DIR} 1>/dev/null 2>&1
        if [[ -f "${_SRC_DIR}/${INSTALL_ALL_REQS_SCRIPT}" ]]; then
            echo "Found \"${_SRC_DIR}/${INSTALL_ALL_REQS_SCRIPT}\". Running it now."
            # NOTE: This "all" script will also patch the requirements libraries if needed.
            bash ${_SRC_DIR}/${INSTALL_ALL_REQS_SCRIPT} --repo-path-dir ${_SRC_DIR}
        else
            # Manually do the essential things that the install_all_requirements script would have done.
            echo "Could not find: \"${_SRC_DIR}/${INSTALL_ALL_REQS_SCRIPT}\""
            echo "Checking for: \"${_SRC_DIR}/${REQS_FILE_NAME}\""
            if [[ -f "${_SRC_DIR}/${REQS_FILE_NAME}" ]]; then
                echo "Found \"${_SRC_DIR}/${REQS_FILE_NAME}\". Running it now."
                pip install -r ${_SRC_DIR}/${REQS_FILE_NAME}
            fi
        fi
    fi
    popd 1>/dev/null 2>&1
}

function create_repo_aliases() {
    set_working_vars__health_check
    alias act_${PROJECT_NAME__HEALTH_CHECK}="activate_repo_venv__${PROJECT_NAME__HEALTH_CHECK}"
    alias init_${PROJECT_NAME__HEALTH_CHECK}="init_and_activate_repo__${PROJECT_NAME__HEALTH_CHECK}"
    unset_venv_vars
}

# Call the function to create the aliases for all the repos.
create_repo_aliases

alias deact="deactivate && \
             popd 1>/dev/null 2>&1 && \
             unset_venv_vars"
