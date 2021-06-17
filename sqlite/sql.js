const pStep = Module.findExportByName(null, 'sqlite3_step');
const pExpand = Module.findExportByName(null, 'sqlite3_expanded_sql');
const pFree = Module.findExportByName(null, 'sqlite3_free');


if (pStep.isNull() || pExpand.isNull() || pFree.isNull()) {
  console.error('failed to find libsqlite3');
} else {
  const expand = new NativeFunction(pExpand, 'pointer', ['pointer']);
  const free = new NativeFunction(pFree, 'void', ['pointer']);
  const r = new ApiResolver('module');

  for (const match of r.enumerateMatchesSync('exports:*!sqlite3_step')) {
    let previous = NULL;

    Interceptor.attach(match.address, {
      onEnter(args) {
        const stmt = args[0];
        if (stmt.isNull() || stmt.equals(previous)) return;

        const sql = expand(stmt);
        if (sql.isNull()) return;
        console.log('>', sql.readUtf8String());

        free(sql);
        previous = stmt;
      }
    });
  }
}
