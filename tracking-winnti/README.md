# Tracking Winnti — article package

Start with **tracking-winnti.md**. Keep the **assets/** directory beside it so the seven images resolve in Obsidian, VS Code or another Markdown viewer.

## Contents

- `tracking-winnti.md`: the article, with source links and image descriptions.
- `assets/`: seven original PNG diagrams, each 1800 pixels wide.
- `detections/tsmsisrv-image-load.yml`: the Sigma example shown in the article.
- `detections/winnti-string-cluster.yar`: the derivative YARA example shown in the article.

## Moving the article to the blog

- Add your normal Jekyll front matter when placing it in `_posts/`.
- Move the images into your blog's asset directory and update their Markdown paths to match that location.
- Keep the captions and source links with the images.

## Detection status

Both rules are illustrative research drafts. YAML parsing, required field values and consistency with the article were checked. The YARA rule was not compiled; neither rule was tested against malware, a benign corpus or an operational SIEM. Preserve those limits if you reuse the examples.

The article is a source-based threat-intelligence analysis, with each campaign kept separate. The diagram arrows are conceptual explanations of the cited reporting.
