# REPO_SETUP.md — make your repo look alive (10 minutes, once)

You own this code. When you push it to GitHub, five small settings turn the repo from
"a folder of files" into a project a stranger trusts at first glance.

## 1 · Turn the CI badge on
`.github/workflows/verify.yml` already re-runs the full offline proof on every push — the same
`python verify.py` you run locally, nothing CI-special. After your first push: open `README.md`,
find the commented badge near the top, uncomment it, and replace `YOUR-ORG/YOUR-REPO` with your
own slug. A green rectangle that means "this repo re-proves itself on every change".

## 2 · Description
Repo → About → Description. A suggestion that is simply true:

> A complete, verified backend in 3 languages — 43 domains, 169 identical
> routes, proves itself offline: `python verify.py`

## 3 · Topics
Repo → About → Topics — these are the searches people actually type:

`backend` `api` `starter` `boilerplate` `fastapi` `golang` `nodejs` `sqlite` `postgres`
`multi-tenant` `ai-agents` `self-verifying`

## 4 · Social preview (the money shot)
Repo → Settings → Social preview (1280×640). Don't design anything: screenshot the GREEN
`python verify.py` output. The proof *is* the pitch.

## 5 · Cut a release
Tag the edition so "Releases" isn't zero:

    git tag edition-1c7ca5fc0e0b55aa
    git push --tags

Then draft a release from the tag with three honest lines: what's inside (43 domains,
169 routes ×3 languages), how to prove it (`python verify.py`), where to start (`TOUR.md`).

Bonus, zero effort: the repo already ships `.devcontainer/`, so the GitHub **Code → Codespaces**
button gives any evaluator all three toolchains in a browser tab — `python verify.py` works there
before they install anything locally.
