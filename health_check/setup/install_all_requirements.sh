#!/bin/bash
#
# Installs the requirements.txt for this project and any submodule as well.
#
# Usage: install_all_requirements.sh --repo-path-dir /path/to/this-repo
#

SCRIPT_PATH=$(cd "$(dirname "${0}")" && pwd)
SCRIPT_NAME=$(basename "${0}")
VERSION="1.1"

REPO_PATH_DIR=""
REQS_FILE_NAME="requirements.txt"

function usage() {
    echo ""
    echo "Usage: install_all_requirements.sh --repo-path-dir /path/to/this-repo"
    echo ""
}

# Parse command line args.
while (( "$#" )); do
    case "$1" in
        -h|--help)
            usage
            exit 0
            shift;;
        -p|--repo-path-dir)
            REPO_PATH_DIR="${2}"
            shift 2;;
        # Catch all other args so that we can pass them along.
	      *)
            ALL_OTHER_ARGS="${ALL_OTHER_ARGS} ${1}";
            shift;;
    esac
done

if [[ "${REPO_PATH_DIR}" == "" ]]; then
    echo ""
    echo "ERROR: Missing required argument: --repo-path-dir"
    usage
    exit 1
fi

function install_reqs() {
    REQS_FILE="${1}"
    SUBMODULE_NAME=${2}
    echo ""
    echo "=========================================================================="

    if [[ -f "${REQS_FILE}" ]]; then
        if [[ "${SUBMODULE_NAME}" == "" ]]; then
            echo "Installing requirements for this repo."
        else
            echo "Installing requirements for submodule: ${SUBMODULE_NAME}"
        fi
        pip install -r "${REQS_FILE}" 2>&1
    else
        if [[ "${SUBMODULE_NAME}" == "" ]]; then
            echo "Skipping installation of requirement because no requirements file was found: \"${REQS_FILE}\""
        else
            echo "Skipping installation of requirement because no requirements file was found: \"${SUBMODULE_NAME}\""
        fi
    fi
}

function install_reqs_parent_repo() {
    install_reqs "${REPO_PATH_DIR}/${REQS_FILE_NAME}"
}

function install_reqs_submodule_repos() {
    # Loop through all the submodule repos and install their requirements.txt (if it exists).
    if [[ -d "${GIT_SUBMODULES}" ]]; then
        SUBMODULES_DIR="${REPO_PATH_DIR}/submodules"
        for SUBMODULE_DIR in ${GIT_SUBMODULES}/*; do
            SUBMODULE_NAME=$(basename ${SUBMODULE_DIR})
            SUBMODULE_REQS_FILE="${SUBMODULES_DIR}/${SUBMODULE_NAME}/${REQS_FILE_NAME}"
            install_reqs "${SUBMODULE_REQS_FILE}" "${SUBMODULE_NAME}"
        done
        echo ""
    else
        echo ""
        echo "=========================================================================="
        echo "No submodules found in this repo. Skipping submodule requirements."
    fi
}

# Verify that the repo path exists.
if [[ ! -d "${REPO_PATH_DIR}" ]]; then
    echo ""
    echo "ERROR: Repo path cannot be found: \"${REPO_PATH_DIR}\""
    exit 1
fi

# Set the .git submodules command to use the correct path.
GIT_SUBMODULES="${REPO_PATH_DIR}/.git/modules/submodules"

# Install requirements for this repo.
install_reqs_parent_repo
# Install any requirements for submodules.
install_reqs_submodule_repos

echo ""

exit 0
