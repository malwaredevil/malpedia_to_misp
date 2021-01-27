import git
import globals as gv
import os
import sys


def clone_misp_galaxy():
    try:
        #print("f(x) clone_misp_galaxy: CLONING MISP GALAXIES")
        git.Repo.clone_from("git@github.com:MISP/misp-galaxy.git", gv._MISP_GALAXY_GIT)

        
    except Exception as e:
        print("f(x) clone_misp_galaxy: {}".format(e))
        sys.exit(e)


def pull_malpedia_git():
    try:
        #print("f(x) pull_malpedia_git: PULLING MALPEDIA")
        gMalpedia = git.cmd.Git(gv._MALPEDIA_REPOSITORY)
        gMalpedia.pull()

        
    except Exception as e:
        print("f(x) pull_malpedia_git: {}".format(e))
        sys.exit(e)


def clone_mitre_git():
    try:
        #print("f(x) clone_mitre_git: CLONING MITRE DATA")
        git.Repo.clone_from("git@github.com:mitre/cti.git", gv._MITRE_GIT)

        
    except Exception as e:
        print("f(x) clone_mitre_git: {}".format(e))
        sys.exit(e)

if __name__ == '__main__':
    print("GIT FUNCTIONS")



    
