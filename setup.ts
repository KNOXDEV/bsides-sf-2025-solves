#!/usr/bin/env -S deno run --allow-read --allow-write
// his sets up the directory structure I want for my solutions automatically.
// Disclosure: the entire file is 80% vibecoded

import { parse } from "jsr:@std/yaml@1.0.5";
import { ensureDir } from "jsr:@std/fs@1.0.14";
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
  const categoryTag = tags.map((tag) => tag.toLowerCase()).find((tag) => !difficultyTags.includes(tag));
  return categoryTag || "misc";
}

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

      // Create solution directory structure
      const solutionDir = path.join(solutionsDir, category, `${difficulty} - ${challengeName}`);
      await ensureDir(solutionDir);

      // Create symlink to distfiles
      const challengeDir = path.dirname(metadataPath);
      const distfilesSource = path.resolve(challengeDir, "distfiles");
      const distfileSourceRelative = path.relative(solutionDir, distfilesSource);
      const distfilesLink = path.join(solutionDir, "distfiles");

      await Deno.symlink(distfileSourceRelative, distfilesLink);

      console.log(`Created: ${distfilesLink} -> ${distfileSourceRelative}`);

      // Add challengefiles symlink as well, we may need to deploy infra (locally)
      const challengeSource = path.resolve(challengeDir, "challenge");
      const challengeSourceRelative = path.relative(solutionDir, challengeSource);
      const challengeLink = path.join(solutionDir, "src")
      await Deno.symlink(challengeSourceRelative, challengeLink);
      console.log(`Created: ${challengeLink} -> ${challengeSourceRelative}`);

      // Add Readme
      const readmeFile = path.join(solutionDir, "README.md");
      await Deno.writeTextFile(readmeFile, `# ${metadata.name}\nOriginal Prompt:\n\`\`\`\n${metadata.description}\`\`\``);

    } catch (error) {
      console.error(`Error processing ${metadataPath}:`, error);
    }
  }

  console.log("\nDone! Solution structure created.");
}

if (import.meta.main) {
  main();
}
