# Dependency-Check Analizer

### Capabilities:
(Until now, it works only with json files)

- Show summary from json file
```node index.js file.json```

- Show summary from json file list
```
node index.js file1.json file2.json
node index.js $(find ./DependencyCheck -name "*.json")
```

- Comparison between two json files
```
node index.js (compare | c) file1.json file2.json
```


#### TODO:

- Comparison between two folders