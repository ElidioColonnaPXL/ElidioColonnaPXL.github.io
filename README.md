# The Guarded Kernel

A personal blue-team blog about incident analysis, detection principles, and APT research.

This is a small, custom Jekyll website for GitHub Pages. It starts with Home and About, and automatically lists Markdown posts when you add them.

## Publish the website

1. Open this repository's **Settings → Pages**.
2. Under **Build and deployment**, choose **Deploy from a branch**.
3. Select **main** and **/ (root)**, then click **Save**.
4. Check the **Actions** tab for the Pages build. Once it succeeds, visit:
   https://elidiocolonnapxl.github.io

Publication can take a few minutes. You do not need to install Ruby or a web server to publish through GitHub.

## Add the original logo

Upload the original image, unchanged, to:

`assets/images/theguardedkernellogo.png`

The header automatically displays that file once it exists. Until then, it uses a text title with a green terminal prompt, so there is no broken image.

In GitHub, open **assets → images**, choose **Add file → Upload files**, select the PNG, and commit it to main. Keep the filename exactly as shown.

## Edit the pages

| What to change | File |
| --- | --- |
| About text | `about.md` |
| Homepage introduction and topics | `index.html` |
| Colours, spacing, fonts | `assets/css/style.css` |
| Blog name, description, GitHub link | `_config.yml` |
| Shared header and footer | `_layouts/default.html` |

The About page contains a short starter draft. Review it before publishing.

## Write an article

Create a file in `_posts` named `YYYY-MM-DD-your-article-title.md`. Replace the date with your intended publication date; future-dated posts stay hidden until the site is rebuilt on or after that date.

For example, `_posts/2026-10-21-my-first-investigation.md`:

```markdown
---
title: "My first investigation"
date: 2026-10-21 12:00:00 +0200
category: "Incident analysis"
description: "A short description of what this article covers."
---

## Context

Write your article here in Markdown.

## Evidence

Explain what you observed and link your sources.

## What I learned

Record the useful conclusions and any limitations.
```

Committing a published post to main triggers a rebuild. The homepage adds it automatically, newest first.

To keep a post out of the public website, add `published: false` to its front matter. **The Markdown source is still visible in this public repository.** Keep private working drafts outside the repository.

For screenshots, upload images under `assets/images/` and reference them in Markdown:

```markdown
![Description of the evidence]({{ '/assets/images/evidence.png' | relative_url }})
```

Use fenced code blocks with a lower-case language name, such as `powershell`, `bash`, `python`, `json`, or `yaml`.

## Optional local preview

If Ruby and Bundler are already installed:

```bash
bundle install
bundle exec jekyll serve
```

Then open http://127.0.0.1:4000. GitHub Pages also builds the site for you, so this local setup is optional.

## Design

- Dark background, monospace type, restrained green accents.
- Responsive layout and keyboard focus styles.
- Shared layouts for pages and articles.
- No client-side JavaScript, analytics, external font requests, or additional theme dependency.

## References

- [GitHub Pages quickstart](https://docs.github.com/en/pages/quickstart)
- [Configuring a publishing source](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site)
- [Adding Jekyll content](https://docs.github.com/en/pages/setting-up-a-github-pages-site-with-jekyll/adding-content-to-your-github-pages-site-using-jekyll)
