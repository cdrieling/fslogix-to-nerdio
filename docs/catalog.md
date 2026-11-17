# The annotation catalogue

The catalogue says what a given FSLogix registry value *means in Nerdio Manager*. It is the
one part of this tool that is knowledge rather than mechanics, and the one part that ages when
NME's UI moves.

It lives in `Export-FSLogixConfig.ps1`, in `Get-BuiltInCatalog`, so the tool stays a single
file to copy onto a session host. `-CatalogPath <file>` loads a JSON file over it: entries with
the same key replace the built-in ones, new keys are added, and nothing is removed.

## Shape

Keys are `<AREA>|<VALUENAME>`, matched case-insensitively. Areas are `Profiles`, `ODFC`,
`Apps`, `Logging`.

```json
{
  "Profiles|ProfileType": {
    "Class": "registry",
    "Note":  "Concurrent access mode. Anything but 0 needs a deliberate decision.",
    "Doc":   "https://learn.microsoft.com/fslogix/reference-configuration-settings",
    "Enum":  { "0": "normal, single session", "3": "read-write and read-only concurrently" }
  },
  "Profiles|VHDLocations": {
    "Class": "field",
    "Field": "FSLogix Profiles path (VHDLocation)",
    "Note":  "Pick the Azure Files share from the drop-down or type a UNC path."
  }
}
```

| Field | Meaning |
|---|---|
| `Class` | `field` — NME has a named control, so the value is **not** put in a paste block. `registry` — FSLogix Registry Options. `editor` — the area's own NME editor (App Service / Log settings). `unmanaged` — not to be carried over at all: either NME does not hold it, or it is install state rather than configuration (`Apps\InstallPath`, `Apps\InstallVersion`). |
| `Field` | the name of the NME control, for `Class: field` |
| `Note` | one sentence, shown on the row. Say what the setting decides and what to watch for, not what the name already says. |
| `Doc` | a link shown on the row |
| `Enum` | value → meaning, rendered under the raw value |

A value with no entry falls back to its area's default: `registry` for Profiles and ODFC,
`editor` for Apps and Logging.

## The rule that keeps it safe

**Entries annotate values that were found; they never decide what is collected.** An entry
that matches nothing is inert. A value with no entry is still read, still shown, and still
lands in the paste block, with a note saying it was not in the catalogue.

So an incomplete catalogue costs commentary, never a setting. Keep that property: do not add
logic that filters, skips or rewrites a value based on a catalogue entry.

## When NME's UI changes

Two kinds of change matter:

1. **A setting gets its own control.** Change its `Class` from `registry` to `field` and add
   `Field`. It then leaves the paste block and appears in the map with the control's name.
2. **A control is renamed.** Change `Field`, and the navigation paths in the "How to rebuild"
   section of `New-HtmlReport` if the path itself moved.

Both are one line each. That is the point of keeping this as data.
