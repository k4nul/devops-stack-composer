# DevOps Stack Composer

DevOps Stack Composer is an orchestration layer for composing the independent
Docker build, Jenkins pipeline, and Kubernetes platform templates maintained in
the sibling template repositories. It derives their inputs from one declarative
application configuration without vendoring the repositories into this project.

The project is under active construction. The stable command entry point is
`devops-stack`; the complete workflow and configuration reference will be added
alongside the adapters.

## Development

Python 3.10 or newer is required.

```bash
python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m devops_stack_composer --version
```

## License

DevOps Stack Composer is released under the MIT License. Resolved source
templates remain independent projects under their own licenses.
