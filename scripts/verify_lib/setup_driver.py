import sys
from pathlib import Path


def main(arguments: list[str]) -> None:
    source, project, revision, name, email, key, preflight, transport, mode = arguments
    # The harness runs this file with -I, so the snapshot's src is found only from here.
    sys.path.insert(0, source)
    from first_commit import setup
    from first_commit.contributor import Contributor

    actions = setup.setup_repository(
        Path(project),
        setup.SetupRequest(
            revision=revision,
            transport=transport,
            dry_run=mode == "dry-run",
            confirmed=True,
            preflight=preflight == "preflight",
        ),
        contributor=Contributor(name=name, email=email, signing_key=key),
    )
    print("\n".join(actions))


if __name__ == "__main__":
    main(sys.argv[1:])
