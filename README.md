# FireFetch

A Firebase audit tool, mostly aimed at mobile apps.

Point it at an APK, an Android package name, or a set of Firebase values you
already have. It checks Remote Config, Realtime Database, Firestore, Cloud
Storage, Auth, and Hosting and tells you what's
exposed.

## Install

```bash
pipx install firefetch
```


## Use it

```bash
# you already have the apk
firefetch apk app-release.apk

# you only know the package name
firefetch apk com.example.app

# no apk; just creds you already have
firefetch manual --project-id foo --api-key AIzaSy... --app-id 1:1234:android:abc
```

Handy flags: `--json out.json` for a structured dump, `--no-write` to skip
write probes (on by default; they write a tiny payload at a unique path and
delete it). `firefetch apk --help` for the rest.

## What you get

![](assets/terminal.png)

## Dev

```bash
git clone https://github.com/bitthebyte/firefetch
cd firefetch
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```
