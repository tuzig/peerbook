from fabric import task
ARC="amd64"
OS="linux"
PB_PATH = '/opt/peerbook'


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
    nr = c.run(f'basename $(readlink {PB_PATH}/next)')
    lr = c.run(f'basename $(readlink {PB_PATH}/live)')
    next = nr.stdout.strip()
    live = lr.stdout.strip()
    print(f"Switching {live} with {next}")
    c.run(f'ln -sfn {PB_PATH}/{next} {PB_PATH}/live')
    c.run(f'ln -sfn {PB_PATH}/{live} {PB_PATH}/next')
    c.run("nginx -s reload")
