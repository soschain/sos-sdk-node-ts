// Flow contract: SOS owns its data contracts and may consume FHIR utilities; source, emitted public modules and the resolved dependency graph must remain independent of every frozen GDC project, including aliases and transitive packages.
import assert from 'node:assert/strict'
import {readFileSync,readdirSync,existsSync} from 'node:fs'
import {resolve,relative} from 'node:path'
import test from 'node:test'
import ts from 'typescript'

const root=process.cwd()
const json=path=>JSON.parse(readFileSync(resolve(root,path),'utf8').replace(/^\uFEFF/u,''))
const forbidden=name=>typeof name==='string'&&(/^(?:npm:)?gdc-/u.test(name)||/\/node_modules\/gdc-/u.test(name))

test('has no direct or aliased GDC package declarations',()=>{
 const manifest=json('package.json'),violations=[]
 const inspect=(value,path)=>{
  if(typeof value==='string'&&/npm:gdc-/u.test(value))violations.push(path)
  else if(value&&typeof value==='object')for(const [key,child] of Object.entries(value)){
   if(forbidden(key))violations.push(`${path}/${key}`)
   inspect(child,`${path}/${key}`)
  }
 }
 for(const section of ['dependencies','devDependencies','peerDependencies','optionalDependencies','overrides','resolutions'])inspect(manifest[section],section)
 assert.deepEqual(violations,[],'SOS package declarations must not depend on frozen GDC projects')
})

test('does not import or re-export GDC from source or emitted modules',()=>{
 const violations=[]
 const inspectFile=path=>{
  const source=ts.createSourceFile(path,readFileSync(path,'utf8'),ts.ScriptTarget.Latest,true)
  const visit=node=>{
   let module
   if(ts.isImportDeclaration(node)||ts.isExportDeclaration(node))module=node.moduleSpecifier
   else if(ts.isCallExpression(node)&&(node.expression.kind===ts.SyntaxKind.ImportKeyword||node.expression.getText(source)==='require'||node.expression.getText(source)==='require.resolve'))module=node.arguments[0]
   if(module&&ts.isStringLiteralLike(module)&&forbidden(module.text))violations.push(`${relative(root,path)}:${module.text}`)
   ts.forEachChild(node,visit)
  }
  visit(source)
 }
 const walk=directory=>{
  if(!existsSync(directory))return
  for(const entry of readdirSync(directory,{withFileTypes:true})){
   const path=resolve(directory,entry.name)
   if(entry.isDirectory())walk(path)
   else if(entry.isFile()&&/\.(?:[cm]?js|tsx?)$/u.test(entry.name))inspectFile(path)
  }
 }
 for(const directory of ['src','dist','build','tests','scripts'])walk(resolve(root,directory))
 assert.deepEqual(violations.slice(0,16),[],`SOS source and emitted modules contain ${violations.length} forbidden GDC references`)
})

test('has no transitive GDC packages in its registry lockfile',()=>{
 const lock=json('package-lock.json')
 const violations=Object.entries(lock.packages||{}).filter(([path,entry])=>/(?:^|\/)node_modules\/gdc-[^/]+$/u.test(path)||forbidden(entry.name)).map(([path])=>path)
 assert.deepEqual(violations.slice(0,16),[],'A wrapper or indirect package must not reintroduce GDC into SOS')
})
