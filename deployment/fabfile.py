from fabric import task

@task
def deploy_pb(c):
    '''Deploys the next version of the Peerbook server to the next service'''
    next = c.run('basename $(readlink /opt/peerbook/next)').stdout
    try:
        c.run('unlink /opt/peerbook/next/peerbook')
    except:
        pass
    with c.cd('../'):  # Move to the parent directory
        c.local('GOOS=linux GOARCH=amd64 go build -o deployment/peerbook .')
    c.put('peerbook', '/opt/peerbook/next')
    c.sudo(f'supervisorctl restart pb-{next}')
    c.sudo("nginx -s reload")

@task
def deploy_host(c):
    '''wIP: Deploys the host archive to the next service'''
    with c.cd('./host_archive'):
        c.local('tar -czf ../archive.tar.gz .')
    c.put('archive.tar.gz', '.')
    c.run('tar -xzf archive.tar.gz -C /')

@task
def switch(c):
    '''Switches the live service and the next'''
    # get the target of the next symbolic link
    next = c.run('basename $(readlink /opt/peerbook/next)')
    live = c.run('basename $(readlink /opt/peerbook/live)')
    c.run(f'ln -sfn {next} /opt/peerbook/live')
    c.run(f'ln -sfn {live} /opt/peerbook/next')
    c.sudo("nginx -s reload")
