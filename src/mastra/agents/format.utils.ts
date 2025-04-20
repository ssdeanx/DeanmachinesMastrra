import { XMLParser } from 'fast-xml-parser';
import YAML from 'yaml';
import Database from 'better-sqlite3';

export type SupportedFormat = 'json' | 'xml' | 'yaml' | 'txt' | 'md' | 'sqlite' | 'db';

/**
 * Parses input data from various formats.
 * For 'sqlite'/'db', input should be the path to the SQLite db file; returns all rows from 'memory' table.
 * Extend as needed to support other tables/queries.
 */
export function parseInput(input: string, format: SupportedFormat): any {
  switch (format) {
    case 'json':
      return JSON.parse(input);
    case 'xml': {
      const parser = new XMLParser();
      return parser.parse(input);
    }
    case 'yaml':
      return YAML.parse(input);
    case 'txt':
    case 'md':
      return input; // passthrough for plain text and markdown
    case 'sqlite':
    case 'db': {
      // input is the path to the db file
      const db = new Database(input, { readonly: true });
      // Read all rows from 'memory' table by default
      const rows = db.prepare('SELECT * FROM memory').all();
      db.close();
      return rows;
    }
    default:
      throw new Error(`Unsupported format: ${format}`);
  }
}

export function stringifyOutput(obj: any, format: SupportedFormat): string {
  switch (format) {
    case 'json':
      return JSON.stringify(obj, null, 2);
    case 'xml': {
      const { XMLBuilder } = require('fast-xml-parser');
      const builder = new XMLBuilder();
      return builder.build(obj);
    }
    case 'yaml':
      return YAML.stringify(obj);
    case 'txt':
    case 'md':
      return typeof obj === 'string' ? obj : String(obj); // passthrough
    default:
      throw new Error(`Unsupported format: ${format}`);
  }
}
