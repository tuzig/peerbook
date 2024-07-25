from fabric import task

@task
def deploy_next(c):
    '''Deploys the next version of the Peerbook server to the next service'''
    c.local('go generate . ; go build .')
    c.sudo('unlink /opt/peerbook/next/peerbook')
    c.put('peerbook', '/opt/peerbook/next')
    c.run(f'supervisorctl restart pb-{next}')

@task
def switch(c):
    '''Switches the live service and the next'''
    # get the target of the next symbolic link
    next = c.run('basename $(readlink /opt/peerbook/next)')
    live = c.run('basename $(readlink /opt/peerbook/live)')
    c.sudo(f'ln -sfn {next} /opt/peerbook/live')
    c.sudo(f'ln -sfn {live} /opt/peerbook/next')
    c.sudo("nginx -s reload")
