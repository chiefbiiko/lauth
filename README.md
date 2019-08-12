# superauth

...

## bike-shed demo

```
curl -sSL https://denopkg.com/chiefbiiko/dynamodb/start_db.sh | bash
deno run --allow-env --allow-net ./setup_db.ts
deno run --allow-read --allow-env --allow-net ./setup_server.ts &
# visit localhost:4190 and start playing around
```

# License

[MIT](./LICENSE)
