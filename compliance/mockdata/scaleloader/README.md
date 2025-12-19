# Scaleloader

The scale loader writes simulated data to ES for the purposes of testing the reporter.

It can be configured with a scenario which can contain multiple playbooks which can contain multiple plays. The scenario defines the start and duration for which data will be generated and scale sizes and churn rate of each playbook.

Elastic search target is configured with ELASTIC_HOST and ELASTIC_PORT, and any other configuration possible with the pkg/elastic.

Example run command (ran from compliance repo root):

```bash
go run cmd/mockdata-scaleloader/scaleloader.go --playbook-dir mockdata/scaleloader/playbooks --scenario mockdata/scaleloader/scenario.demo --log-level debug
```

playbook-dir:

- The directory where all playbooks will be read from.
- Defaults to the current directory.

scenario:

- File with the scenario definition.
- This can also be specified as the argument to scaleloader.

## Running as a pod

The file `scaleloader.yaml` is a manifest that will create a ConfigMap, NetworkPolicy, and a pod. The ConfigMap will be mounted as a scenario file in the pod which will if RUN_SCENARIO is true then scaleloader will be ran with the scenario. The NetworkPolicy that is created is to allow scaleloader to access Elasticsearch.

If you need to add more playbooks then you can add them to the playbooks folder in this directory and then build a scaleloader image.

## Scenario

Example scenario:

```yaml
playbooks:
  - name: demo-pod-playbook
    playbookscale: 1
    playscale: 2
    churnrate: 8
  - name: demo-other-playbook
    playbookscale: 1
    podscale: 2
    churnrate: 1

duration: 5h
```

playbooks: List of playbooks and the scale and churn configuration for them

- name: the name of the folder in the `playbook-dir` that will be loaded.
- playbookscale: The number of instances of the playbook that will be created, each separated as <namespace>-<instance>.
- playscale: The number of instances of each scaled play (see Plays:Scaled below).
- churnrate: The number of iterations of each playbook instance that will be executed per day.

duration: Time period for which data will be generated.

## Playbooks

Here is an example playbook directory structure:

```text
├── demo-other-playbook
│   ├── nonscaled
│   │   └── c
│   │       ├── 00-np.yaml
│   │       ├── 01-modify.yaml
│   │       └── 02-modify.yaml
│   └── scaled
│       └── c
│           ├── 00-np.yaml
│           ├── 01-modify.yaml
│           ├── 02-modify.yaml
│           ├── 03-hep-update.yaml
│           └── 04-k8s-ep.yaml
└── demo-pod-playbook
    └── scaled
        ├── a
        │   ├── 01-create.yaml
        │   ├── 02-update.yaml
        │   └── 03-delete.yaml
        └── b
            ├── 01-create.yaml
            └── 02-delete.yaml
```

The namespace for each playbook can be inserted into each resource by putting `{{.Namespace}}` where the namespace should go. This will work not only in metadata.namespace but in any value string (it will not work as a key though).

### Plays

Each subfolder under `scaled` or `nonscaled` is a Play. A play is a sequence of resource CRUD steps. A Play does not have to be all for the same resource or type.

During an instance of a Playbook (one cycle through all plays), each step in the contained plays will be turned into the appropriate audit message and written to ES, the next step will come from a randomly selected the play (from the ones that still have steps left) but each step in a play will be used in order.

The steps will be loaded in order, defined by the XX at the beginning of each filename (with 00 being reserved for initialization). More than 99 steps in a play is currently not supported.

To specify that a resource is deleted then add `action: delete` to at the top of the file. Anything specified for the action will be used as the verb for the audit event, the default is update.

#### Initial playbook state

Any files in the scaled or nonscaled plays starting with `00-` will be loaded in the snapshot that is written at the start time.

#### scaled

The `scaled` directory under each playbook can have multiple Play folders.  Each play in the scaled directory will be "scaled" by the `playscale` specified in the scenario file, meaning each play will have however many instances created as specified by the `playscale`. The names used for resources in a scaled play should include `{{.ScaleId}}` which will differentiate the resources in one instance of the play from the next.

Example:

If the demo-pod-playbook from the example above was specified with a `playscale` of 3. There would be 3 instances of `a`: a-0, a-1, a-2 and 3 instances of `b`: b-0, b-1, b-2.

#### nonscaled

Plays in the nonscaled directory will not be scaled.
