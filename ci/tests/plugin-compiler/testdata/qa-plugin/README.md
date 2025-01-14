# QA Plugin

The only difference between this and other plugins is that this one does
not provide a go.mod. This means a slightly different build path is
tested for the plugin compiler, ensuring coverage for when no go.mod is
provided.
