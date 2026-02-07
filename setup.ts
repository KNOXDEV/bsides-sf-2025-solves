#!/usr/bin/env -S deno run --allow-read --allow-write
// his sets up the directory structure I want for my solutions automatically.
// Disclosure: the entire file is 80% vibecoded

import { parse, stringify } from "jsr:@std/yaml@1.0.5";
import { ensureDir, exists } from "jsr:@std/fs@1.0.14";
import * as path from "jsr:@std/path@1.0.8";

interface ChallengeMetadata {
  version: string;
  name: string;
  author: string;
  flag: string;
  description: string;
  value: number;
  tags: string[];
  port?: number;
  protocol?: string;
  use_podperconn?: boolean;
  security?: {
    allow_run_as_root: boolean;
  };
}

function getDifficulty(metadata: ChallengeMetadata): string {
  if (metadata.value <= 250 || metadata.tags.includes("101")) return "easy";
  return "hard";
}

function getCategory(tags: string[]): string {
  // Use the first non-difficulty tag as the category
  // Filter out common difficulty indicators
  const difficultyTags = ["101", "beginner", "easy", "medium", "hard"];
  const categoryTag = tags.map((tag) => tag.toLowerCase()).find((tag) =>
    !difficultyTags.includes(tag)
  );
  return categoryTag || "misc";
}

const DEFAULT_SERVICE_YAML = {
  services: {
    challenge: {
      build: {
        context: "./src/challenge",
        dockerfile: "Dockerfile"
      },
      ports: [] as string[],
      restart: "unless-stopped"
    }
  }
};

async function main() {
  const challengesDir = "./challenges";
  const solutionsDir = "./solutions";

  // Ensure solutions directory exists
  await ensureDir(solutionsDir);

  // Find all metadata.yml files
  const metadataFiles: string[] = [];
  for await (const entry of Deno.readDir(challengesDir)) {
    if (entry.isDirectory) {
      const metadataPath = path.join(challengesDir, entry.name, "metadata.yml");
      try {
        await Deno.stat(metadataPath);
        metadataFiles.push(metadataPath);
      } catch {
        // metadata.yml doesn't exist, skip
      }
    }
  }

  console.log(`Found ${metadataFiles.length} challenges`);

  for (const metadataPath of metadataFiles) {
    try {
      const content = await Deno.readTextFile(metadataPath);
      const metadata = parse(content) as ChallengeMetadata;

      const challengeName = metadata.name;
      const difficulty = getDifficulty(metadata);
      const category = getCategory(metadata.tags);

      // skip on-site challenges
      if (category == "on-site") {
        continue;
      }

      // Create solution directory structure
      const solutionDir = path.join(
        solutionsDir,
        category,
        `${difficulty} - ${challengeName}`,
      );
      await ensureDir(solutionDir);

      // Create symlink to distfiles
      const challengeDir = path.dirname(metadataPath);
      const challengeDirRelative = path.relative(solutionDir, challengeDir);
      const sourceLink = path.join(solutionDir, "src");
      // always recreate link
      if(await exists(sourceLink))
        await Deno.remove(sourceLink)
      await Deno.symlink(challengeDirRelative, sourceLink);
      console.log(`Created: ${sourceLink} -> ${challengeDirRelative}`);

      // Add Readme IF one does not already exist
      const readmeFile = path.join(solutionDir, "README.md");
      if (!(await exists(readmeFile))) {
        await Deno.writeTextFile(
          readmeFile,
          `# ${metadata.name}\nOriginal Prompt:\n\`\`\`\n${metadata.description}\`\`\``,
        );
      }

      // add a simple starter docker-compose if this challenge needs a service deployed
      if (metadata.port) {
        const composeFile = path.join(solutionDir, "docker-compose.yml");
        if(!(await exists(composeFile))) {
          const serviceConfig = structuredClone(DEFAULT_SERVICE_YAML);
          serviceConfig.services.challenge.ports.push(`8080:${metadata.port}`);
          await Deno.writeTextFile(composeFile, stringify(serviceConfig));
        }
      }
    } catch (error) {
      console.error(`Error processing ${metadataPath}:`, error);
    }
  }

  console.log("\nDone! Solution structure created.");
}

if (import.meta.main) {
  main();
}
