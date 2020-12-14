def commit_database():
    import sys
    from subprocess import call

    call("git add data.csv", shell=True)

    call("git commit -m 'New Occurence in the database'", shell=True)
    call("git push -u origin main", shell=True)