## Configuration of _dnbd3-server_
The dnbd3-server is started according to the following command line call.

```shell
dnbd3-server -c <CONFIG_DIR>
```

An operation of the dnbd3-server requires a configuration directory to provide proper functionality. The configuration directory should contain two configuration files, namely the _alt-servers_ and the _server.conf_ file.


## Configuration file _alt-servers_
The _alt-servers_ configuration file specifies the list of known alt-servers for the dnbd3-server. The configuration in the file is specified the INI file format as shown in the following.

```ini
[Address]
comment=Whatever
for=purpose # where purpose is either "client" or "replication"
namespace=some/path/
```

All fields in an INI section are optional. If the `for` key is missing, the dnbd3-server will be used for replication and will be propagated to clients that request a list of alt servers. The `namespace` key can be specified multiple times per INI section. If this key is missing, the server will be used for all image names. Otherwise, it will only be used for images which's name starts with one of the given strings.

If the dnbd3-server is not running in proxy mode, this file won't do much.


## Configuration file _server.conf_
The _server.conf_ file is the main configuration file of the dnbd3-server. The configuration in the file is specified the INI file format as shown in the following.

```ini
[dnbd3]
basePath=/srv/openslx/dnbd3 # virtual root of image files
serverPenalty=1234 # artificial acceptance delay for incoming server connections (µs)
clientPenalty=2345 # artificial acceptance delay for incoming client connection (µs)
isProxy=true # enable proxy mode - will try to replicate from alt-servers if a client requests unknown image
uplinkTimeout=1250 # r/w timeout for connections to uplink servers
```


## Development notes

### Resource locking in dnbd3
The order of aquiring multiple locks is very important, as you'll produce a possible deadlock if you do it in the wrong order. Take very good care of locking order if you have lots of functions that call each other. You might lose track of what's going on.


#### dnbd3-fuse
This is a list of used locks, in the order they have to be aquired if you must hold multiple locks.

```
mutexInit
newAltLock
altLock
connection.sendMutex
requests.lock
```


#### dnbd3-server
This is a list of used locks, in the order they have to be aquired if you must hold multiple locks. Take a look at the lock priority defines in _src/server/locks.h_ for the effective order.

```
reloadLock
loadLock
remoteCloneLock
_clients_lock
_clients[].lock
integrityQueueLock
imageListLock
_images[].lock
uplink.queueLock
altServersLock
client.sendMutex
uplink.rttLock
uplink.sendMutex
aclLock
initLock
dirLock
```

If you need to lock multiple clients or images or etc at once, lock the client with the lowest array index first.

If the program logic would require to aquire the locks in a different order, you have to rework the code. For example, if you hold the lock for client 10 and you need to look up some other client. You must not simply fetch the _clients_lock now and then iterate over the clients until you find the one you need, as it violates the above order to first lock on the clients array and then the clients lock. Instead, you need to release client 10's lock, then lock on _clients_lock and iterate over the clients. Now you check if you either encounter the client you originally held the lock on, or the client you are looking for. You immediately lock on those two. You can then release the _clients_lock and work with both clients.
This described implementation advice is visualized in the following pseudo C code.

```C
/* client10 is assumed to be a pointer to a client, which happens to be at index 10 */
lock (client10->lock);
/* ... */
/* we need another client */
unlock(client10->lock);

lock(_clients_lock);
client clientA = NULL, clientB = NULL;
for (i = 0; i < _num_clients; ++i) {
	if (client[i] == client10) {
		clientA = client[i];
		lock(clientA.lock);
	} else if (client[i].something == <whatever>) {
		clientB = client[i];
		lock(clientB.lock);
	}
}
unlock(_clients_lock);

if (clientA && clientB) {
    /* make sure we actually found both */
	/* do something important with both clients */
}

if (clientA)
    unlock(clientA.lock);
if (clientB)
    unlock(clientB.lock);
```
