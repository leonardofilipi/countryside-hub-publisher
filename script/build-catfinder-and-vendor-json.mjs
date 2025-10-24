// scripts/build-catfinder-and-vendor-json.mjs
// Gera `data/catfinder.json` e `data/vendor_categories.json` a partir de `data/csh_categories.csv`

import fs from 'fs';
import path from 'path';
import { parse } from 'csv-parse/sync';

const ROOT = new URL('..', import.meta.url).pathname;
const DATA_DIR = path.join(ROOT, 'data');
const CSV_PATH = path.join(DATA_DIR, 'csh_categories.csv');
const CATFINDER_PATH = path.join(DATA_DIR, 'catfinder.json');
const VENDOR_PATH = path.join(DATA_DIR, 'vendor_categories.json');

function slugify(txt) {
  return String(txt || '')
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

function readCSV() {
  const raw = fs.readFileSync(CSV_PATH, 'utf8');
  const rows = parse(raw, { columns: true, skip_empty_lines: true, bom: true });
  const mapCol = (row, key) => {
    const k = Object.keys(row).find(c => c.trim().toLowerCase() === key);
    return k ? String(row[k]).trim() : '';
  };
  return rows.map(r => ({
    categoria: mapCol(r, 'categoria'),
    subcategoria: mapCol(r, 'subcategoria'),
    item: mapCol(r, 'item'),
  }));
}

function buildFromRows(rows) {
  const cfItems = [];
  const seen = new Set();
  const byCat = new Map();

  for (const r of rows) {
    if (!r.categoria) continue;

    const cName = r.categoria;
    const cSlug = slugify(cName);
    const cUrl = `/collections/${cSlug}`;
    const keyCat = `cat:${cSlug}`;
    if (!seen.has(keyCat)) {
      cfItems.push({ name: cName, slug: cSlug, url: cUrl });
      seen.add(keyCat);
    }
    if (!byCat.has(cSlug)) {
      byCat.set(cSlug, { name: cName, slug: cSlug, url: cUrl, children: [] });
    }

    if (!r.subcategoria) continue;

    const sName = r.subcategoria;
    const sSlug = slugify(sName);
    const sUrl = `/collections/${sSlug}`;
    const keySub = `sub:${sSlug}`;
    if (!seen.has(keySub)) {
      cfItems.push({ name: sName, slug: sSlug, url: sUrl, parent: cSlug });
      seen.add(keySub);
    }

    const catEntry = byCat.get(cSlug);
    let subRef = catEntry.children.find(x => x.slug === sSlug);
    if (!subRef) {
      subRef = { name: sName, slug: sSlug, url: sUrl, items: [] };
      catEntry.children.push(subRef);
    }

    if (!r.item) continue;

    const iName = r.item;
    const iSlug = slugify(iName);
    const iUrl = `/collections/${sSlug}?filter.p.tag=${iSlug}`;
    const keyItem = `item:${sSlug}:${iSlug}`;
    if (!seen.has(keyItem)) {
      cfItems.push({ name: iName, slug: iSlug, url: iUrl, parent: sSlug });
      seen.add(keyItem);
    }

    if (!subRef.items.find(it => it.slug === iSlug)) {
      subRef.items.push({ name: iName, slug: iSlug, url: iUrl });
    }
  }

  const catfinder = {
    rootAll: {
      slug: 'todas-as-categorias',
      name: 'Todas as Categorias',
      url: '/collections/all',
    },
    items: cfItems,
  };

  const vendor = { categories: Array.from(byCat.values()) };

  return { catfinder, vendor };
}

function main() {
  const rows = readCSV();
  const { catfinder, vendor } = buildFromRows(rows);
  fs.writeFileSync(CATFINDER_PATH, JSON.stringify(catfinder, null, 2), 'utf8');
  fs.writeFileSync(VENDOR_PATH, JSON.stringify(vendor, null, 2), 'utf8');
  console.log('✅ JSONs gerados com sucesso!');
}

main();
