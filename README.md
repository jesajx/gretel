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
curl localhost/
curl localhost/api
```


Once there are some logs, analyze them:
```bash
python3 logparse.py
```
TODO view resulting graph in Gephi.


## TODO

* Instrument a whole website: maybe some python as API server and CrouchDB as db (nginx -> APIserver -> DB).
* Track more syscalls.
* Use randomized gretels ebpf just like in nginx, with metadata (location, etc.) logged.
* fix old code in logparse.py to export to Gephi.
