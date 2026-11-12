<p align="center">
  <a href="https://github.com/brunonlinespace/brunonlinespace/blob/main/linspectacles/crypto-registry.png">
    <img
      src="https://raw.githubusercontent.com/brunonlinespace/brunonlinespace/main/linspectacles/crypto-registry.png"
      alt="Crypto Registry screenshot"
      width="900"
    >
  </a>
</p>

# Crypto Registry

**Expose. Explore. Explain.**

Crypto Registry is a read-only inspector for the Linux Kernel Crypto API registry exposed by `/proc/crypto`.

Current release: **0.0.8**

Repository: <https://github.com/linspectacles/crypto-registry>

## What Crypto Registry is

Crypto Registry answers a focused question: **which cryptographic implementations are registered with the running kernel, and what properties does the kernel report for each one?**

It keeps acquisition and interpretation close to the Linux interfaces actually used by the applet. When a source is unavailable, restricted, or does not report a field, the README does not imply that the applet can manufacture the missing information.

## Highlights

- Every blank-line-delimited `/proc/crypto` record is retained as a separate registry entry.
- Multiple implementations with the same algorithm name remain separate rather than being deduplicated.
- Metadata Details preserves every reported key/value field, including implementation-specific fields.
- Search and category presentation operate on the acquired registry without modifying kernel crypto state.

## Data sources and acquisition

- `/proc/crypto`.

The applet uses those sources according to the acquisition paths implemented in this release. Optional tools or privileged helpers only affect the views/actions that explicitly use them; they are not treated as silent substitutes for unrelated sources.

## Interface

Crypto Registry follows the LinSpectacles inventory + **Metadata Details** pattern where applicable: an acquired inventory remains separate from the details for the selected record, and search/filter controls operate on the data the applet has actually collected.

The applet's **Options** surface provides the presentation/source/about controls implemented by this release, together with export controls where present in the source. Applet-specific actions remain explicit rather than being folded into background collection.

## Read-only and scope boundaries

Registration means an implementation is available to the Kernel Crypto API; it does not prove that a particular workload is using it. Crypto Registry never writes to `/proc/crypto` or changes kernel cryptographic configuration.

## Running from source

The supplied source is directly runnable on Linux. The Python-side requirements are:

- Python 3.
- PyQt6 for the graphical interface.

Create a local virtual environment if you do not already have the required Python packages in the environment you want to use:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install PyQt6
python3 linspectacles_crypto_registry/standalone.py
```

Linux commands, procfs/sysfs interfaces, system services, or optional helpers mentioned in **Data sources and acquisition** are applet-specific runtime inputs. A missing optional source is handled by the applet's existing availability/error path; it is not replaced here with an invented dependency or capability.

No RPM installation instructions are included in this README.

## Source layout and LinSpectacles integration

The applet source is contained in:

```text
linspectacles_crypto_registry/
├── __init__.py
├── standalone.py
├── LICENSE
├── applet.json
├── README.md
└── crypto_registry/
    ├── applet.py
    ├── _support.py
    └── icon.png
```

`applet.json` supplies the LinSpectacles applet identity and entrypoint metadata. `standalone.py` launches the applet directly, while the package's applet factory provides the host-loadable LinSpectacles integration used by the source.

## Configuration

Presentation and inspection preferences are persisted only through the settings mechanisms already implemented by the applet. Persisted UI state does not grant the applet permission to modify the inspected Linux subsystem.

## Scope

Crypto Registry is intentionally specialist. Related Linux information that belongs to another LinSpectacles subsystem remains outside this applet rather than being inferred or duplicated here.

## License

GNU General Public License v3.0 or later. See [`LICENSE`](LICENSE).

## Links

- LinSpectacles organisation: <https://github.com/linspectacles/>
- Repository: <https://github.com/linspectacles/crypto-registry>
- Issues: <https://github.com/linspectacles/crypto-registry/issues>

<p align="center">
  <a href="https://github.com/linspectacles/crypto-registry">
    <img
      src="crypto_registry/icon.png"
      alt="Crypto Registry"
      width="256"
    >
  </a>
</p>
