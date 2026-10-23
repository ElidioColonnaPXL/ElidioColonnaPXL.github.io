# Minimal Mistakes light trial

This branch uses Minimal Mistakes 4.28.1 as a pinned Jekyll remote theme, with a custom pale mint palette and the existing Guarded Kernel content and branding.

The homepage keeps its terminal prompts, three-line heading, article list, and topic descriptions. The topics form a narrow sidebar on desktop and follow the articles on mobile. About and article pages use a readable, centered column. The existing PNG logo is displayed through a CSS colour filter for the light background; its source file is unchanged.

## Preview with Jekyll

With Ruby and Bundler installed:

```sh
bundle install
bundle exec jekyll serve --host 127.0.0.1
```

Open http://127.0.0.1:4000. GitHub Pages can use the configured remote theme and plugins.

`_layouts/default.html` is adapted from the Minimal Mistakes base layout. Its masthead cache includes the page URL so the current navigation link is correct on each page. The custom `_includes/head.html` keeps the existing About SEO title and favicon URL. The domain, About permalink, and article permalink structure are retained.

`assets/css/main.scss` imports Minimal Mistakes and `_sass/_guarded-kernel.scss`. The previous `assets/css/style.css` remains available as a reference but is not loaded by this trial.

This is a local trial branch. It has not been pushed or deployed.
