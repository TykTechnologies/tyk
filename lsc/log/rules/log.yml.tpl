  - id: log.:log:.remove.empty.withFields
    pattern: 'log.WithFields(logrus.Fields{"prefix": ":prefix:"})'
    fix: :log:
    languages:
      - go
    message: Removing prefix single field
    severity: WARNING

  - id: log.:log:.remove.prefix.from.Fields
    pattern: 'log.WithFields(logrus.Fields{"prefix": ":prefix:",$X})'
    fix: |
      :log:.WithFields(logrus.Fields{
      	$X,
      })
    languages:
      - go
    message: Removing prefix from map
    severity: WARNING

