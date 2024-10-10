# Gretel

## How to

```bash
git clone https://github.com/jesajx/gretel.git
git submodule update --init     # download nginx-gretel/
cd nginx-gretel
git switch gretel
```

In one terminal:
```bash
rm -f gretel_bcc.log && sudo python3 gretel_bcc.py
```
and wait for it to say "RECORDING".

Next, in another terminal:
```bash
sudo rm -f nginx{1,2}.logs/*.log && sudo docker-compose up --build
```
and wait for it to start up.

To test, use yet another terminal:
```bash
curl -H 'gretel: 0000000000000005000000000000000000000000000000000000000000000001' localhost/
curl -H 'gretel: 0000000000000005000000000000000000000000000000000000000000000002' localhost/api
```


Once there are some logs, analyze them:
```bash
python3 logparse.py
```
TODO view resulting graph in Gephi.


## TODO

* debug graphs
    * inode cycles, etc.
* Instrument a whole website: maybe some python as API server and CrouchDB as db (nginx -> APIserver -> DB).
* fix old code in logparse.py to export to Gephi.
* allow http gretel-header to not have padding (e.g. 5-0-0-1 instead).
* Track more kernel internals.
* clean up nginx gretel node logging (use human readable names instead of linenumbers)


Further ahead (maybe):
* track inodes more permanently (not just those in memory and also across boots)
* track entire OS (modify kernel instead of using ebpf, modify systemd, bash, etc.)
