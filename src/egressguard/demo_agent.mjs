// A stand-in "agent" using Node's built-in fetch. Proxy and CA come only from the environment.
// usage: node agent_node.mjs <block|redact>
const TOOLS = process.env.AGENT_TOOLS_HOST ?? "tools.example.test";
const UA = "demo-agent/1.0 (dev.user@example.com)";
const scen = process.argv[2];
try {
  const r =
    scen === "block"
      ? await fetch(`https://${TOOLS}/upload`, {
          method: "POST",
          headers: { "User-Agent": UA },
          body: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        })
      : await fetch(`https://${TOOLS}/fetch?q=docs`, { headers: { "User-Agent": UA } });
  console.log(`${r.status} ${(await r.text()).trim().slice(0, 160)}`);
} catch (e) {
  console.log(`ERROR ${e} ${e.cause ?? ""}`);
  process.exit(1);
}
