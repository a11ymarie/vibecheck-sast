# Stand-in for the AI-assistant step in docs/demo/demo.tape: three real fixes to the practice app.
import re, sys
app = sys.argv[1]
def edit(rel, old, new):
    p = f"{app}/{rel}"; s = open(p).read(); assert old in s, (rel, old); open(p, "w").write(s.replace(old, new))
edit("app/api/notes/route.ts",
     "const notes = await prisma.$queryRawUnsafe(`SELECT * FROM \"Note\" WHERE tag = '${tag}'`)",
     "const notes = await prisma.$queryRaw`SELECT * FROM \"Note\" WHERE tag = ${tag}`")
edit("lib/auth.ts",
     "const TOKEN_SECRET = process.env.TOKEN_SECRET || 'demo-app-token-secret'",
     "if (!process.env.TOKEN_SECRET) throw new Error('TOKEN_SECRET is not set')\nconst TOKEN_SECRET = process.env.TOKEN_SECRET")
edit("server/worker.js",
     "res.json({result: eval(req.body.expression)})",
     "res.json({result: Number(req.body.expression)})")
