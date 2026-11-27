import { describe, expect, it } from "vitest";
import { createAdapterBundle } from "./factory.js";

describe("createAdapterBundle", () => {
  it("resolves in-memory adapters for memory backends", () => {
    const bundle = createAdapterBundle({
      environment: "local",
      metadataBackend: "memory",
      graphBackend: "memory",
      evidenceBackend: "memory",
      vectorBackend: "memory",
    });

    expect(bundle.resolutions.map((item) => item.implementation)).toEqual([
      "in-memory",
      "in-memory",
      "in-memory",
    ]);
  });

  it("resolves named backend skeletons for postgres/neo4j/pgvector", () => {
    const bundle = createAdapterBundle({
      environment: "service",
      metadataBackend: "postgres",
      graphBackend: "neo4j",
      evidenceBackend: "s3",
      vectorBackend: "pgvector",
    });

    expect(bundle.resolutions[0]?.descriptor.capabilities).toContain("canonical-write");
    expect(bundle.resolutions[0]?.descriptor.capabilities).toContain("schema-bootstrap");
    expect(bundle.resolutions[0]?.implementation).toBe("sql-first");
    expect(bundle.resolutions[1]?.descriptor.capabilities).toContain("path-query");
    expect(bundle.resolutions[1]?.descriptor.capabilities).toContain("schema-bootstrap");
    expect(bundle.resolutions[2]?.descriptor.capabilities).toContain("similarity-search");
    expect(bundle.resolutions[2]?.descriptor.capabilities).toContain("schema-bootstrap");
    expect(bundle.resolutions[2]?.implementation).toBe("sql-first");
  });

  it("requires an explicit path for local metadata backend", () => {
    expect(() =>
      createAdapterBundle({
        environment: "local",
        metadataBackend: "local",
        graphBackend: "memory",
        evidenceBackend: "memory",
        vectorBackend: "memory",
      }),
    ).toThrow('metadataBackend "local" requires metadataStorePath');
  });

  it("wires neo4j client, pgvector client fallback, and embeddingProvider", async () => {
    const cypherCalls: string[] = [];
    const pgCalls: string[] = [];

    const bundle = createAdapterBundle({
      environment: "service",
      metadataBackend: "postgres",
      postgres: {
        client: {
          async query(sql) {
            pgCalls.push(sql);
            return { rows: [], rowCount: 0 };
          },
        },
      },
      graphBackend: "neo4j",
      neo4j: {
        client: {
          async run(cypher) {
            cypherCalls.push(cypher);
            return { records: [] };
          },
        },
      },
      evidenceBackend: "s3",
      vectorBackend: "pgvector",
      pgvector: {
        embeddingDimension: 2,
        embeddingProvider: {
          dimension: 2,
          embed: async (texts) => texts.map(() => [0.5, 0.5]),
        },
      },
    });

    await bundle.graphStore.delete?.(["atm_1"]);
    await bundle.vectorStore.delete?.(["atm_1"]);

    expect(cypherCalls[0]).toContain("DETACH DELETE");
    expect(pgCalls[0]).toContain("delete from");
  });
});
