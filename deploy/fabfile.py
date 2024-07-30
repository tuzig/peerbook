from fabric import task
ARC="amd64"
OS="linux"

@task
def deploy_pb(c):
    '''Deploys the next version of the Peerbook server to the next service'''
    next = c.run('basename $(readlink /opt/peerbook/next)').stdout
    with c.cd('../'):
        # local go commands
        c.local('go test ./...')
        c.local('./aatp/run')
        c.local(f'GOOS={OS} GOARCH={ARC} go build -o deploy/peerbook .')
    try:
        c.run('unlink /opt/peerbook/next/peerbook')
    except:
        pass
    c.put('peerbook', '/opt/peerbook/next')
    c.sudo(f'supervisorctl restart pb-{next}')
    print(f"Deployed to prompt-collie-free.ngrok-free.app")

@task
def deploy_host(c):
    '''wIP: Deploys the host archive to the next service'''
    # verify the user is ready to deploy
    print("This will deploy the host archive to the next service")
    print("Are you sure you want to continue?")
    response = input("Type 'yes' to continue: ")
    if response != 'yes':
        print("Exiting...")
        return
    with c.cd('./host_archive'):
        c.local('tar -czf ../archive.tar.gz .')
    c.put('archive.tar.gz', '.')
    c.run('tar -xzf archive.tar.gz -C /')
    c.run('supervisorctl reread')
    c.run('supervisorctl restart *')
    c.local('rm archive.tar.gz')

@task
def switch(c):
    '''Switches the live service and the next'''
    # get the target of the next symbolic link
    next = c.run('basename $(readlink /opt/peerbook/next)')
    live = c.run('basename $(readlink /opt/peerbook/live)')
    c.run(f'ln -sfn {next} /opt/peerbook/live')
    c.run(f'ln -sfn {live} /opt/peerbook/next')
    c.sudo("nginx -s reload")
