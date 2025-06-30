# Contributions & Community

For details on contributing, community standards, and licensing, see:

- [Contributing Guidelines](https://github.com/stanfrbd/cyberbro/blob/main/CONTRIBUTING.md)
- [Code of Conduct](https://github.com/stanfrbd/cyberbro/blob/main/CODE_OF_CONDUCT.md)
- [Roadmap](https://github.com/stanfrbd/cyberbro/blob/main/ROADMAP.md)
- [License](https://github.com/stanfrbd/cyberbro/blob/main/LICENSE)

# Checklist when adding a new engine

* Make sure the engine is added to `engines/engine_name.py`.
* Make sure the engine is added to `utils/analysis.py`.
* Make sure the engine has export options in `export.py`.
* Make sure the engine result can be copied to clipboard using the GUI in `static/format_results.js`.
* Make sure every template in `templates/` has corresponding engine result template in `templates/engines_layouts/` - `engine_card.html` and `engine_table.html`.
* Make sure the engine is added in `display_cards.html` and `display_table.html`.
* Make sure the engine is in the GUI form `index.html` with relevant description - alphabetic order.
* Make sure the engine is usable in the graph view in `graph.html`.
* Make sure any API key or configuration needed for the engine is added to `secrets.json`.
* Make sure the engine is documented in `docs/api-keys/Get-Engine-API-Key.md` if relevant.
* Make sure the engine is documented in `docs/quick-start/API-usage-and-engine-names.md`.
