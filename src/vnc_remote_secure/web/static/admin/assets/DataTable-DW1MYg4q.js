import{c as h,u as C,r as x,j as t}from"./index-B8fpaLar.js";/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const S=h("ArrowDown",[["path",{d:"M12 5v14",key:"s699le"}],["path",{d:"m19 12-7 7-7-7",key:"1idqje"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const V=h("ArrowUp",[["path",{d:"m5 12 7-7 7 7",key:"hav0vg"}],["path",{d:"M12 19V5",key:"x0mq9r"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const A=h("ChevronsUpDown",[["path",{d:"m7 15 5 5 5-5",key:"1hf1tw"}],["path",{d:"m7 9 5-5 5 5",key:"sgt6xg"}]]);function z({columns:d,rows:n,rowKey:m,loading:p=!1,error:j=!1,errorText:y,onRetry:c,emptyText:b,emptyAction:u}){const{t:o}=C(),f=y??o("table.errorText"),k=b??o("table.emptyText"),[a,v]=x.useState(null),g=x.useMemo(()=>{if(!n||!a)return n;const e=d.find(s=>s.key===a.key);if(!(e!=null&&e.sortValue))return n;const r=a.dir==="asc"?1:-1;return[...n].sort((s,D)=>{const i=e.sortValue(s),l=e.sortValue(D);return i==null&&l==null?0:i==null?1:l==null?-1:typeof i=="number"&&typeof l=="number"?(i-l)*r:String(i).localeCompare(String(l))*r})},[n,a,d]),N=e=>v(r=>(r==null?void 0:r.key)!==e?{key:e,dir:"asc"}:r.dir==="asc"?{key:e,dir:"desc"}:null);return j?t.jsxs("div",{className:"error-box",role:"alert",children:[f,c&&t.jsx("button",{type:"button",className:"ghost",onClick:c,children:o("common.retry")})]}):p&&!n?t.jsxs("table",{className:"data","aria-busy":"true",children:[t.jsx("thead",{children:t.jsx("tr",{children:d.map(e=>t.jsx("th",{children:e.header},e.key))})}),t.jsx("tbody",{children:Array.from({length:4},(e,r)=>t.jsx("tr",{"aria-hidden":"true",children:d.map(s=>t.jsx("td",{children:t.jsx("span",{className:"skeleton"})},s.key))},r))})]}):t.jsxs("table",{className:"data",children:[t.jsx("thead",{children:t.jsx("tr",{children:d.map(e=>{const r=(a==null?void 0:a.key)===e.key;return t.jsx("th",{"aria-sort":r?a.dir==="asc"?"ascending":"descending":void 0,children:e.sortValue?t.jsxs("button",{type:"button",className:"th-sort",onClick:()=>N(e.key),children:[e.header," ",r?a.dir==="asc"?t.jsx(V,{size:12,"aria-hidden":"true"}):t.jsx(S,{size:12,"aria-hidden":"true"}):t.jsx(A,{size:12,"aria-hidden":"true"})]}):e.header},e.key)})})}),t.jsxs("tbody",{children:[(g??[]).map(e=>t.jsx("tr",{children:d.map(r=>{var s;return t.jsx("td",{title:(s=r.title)==null?void 0:s.call(r,e),className:r.mono?"mono":void 0,children:r.render(e)},r.key)})},m(e))),n&&n.length===0&&t.jsx("tr",{children:t.jsxs("td",{colSpan:d.length,className:"muted",children:[k,u&&t.jsx("div",{className:"empty-action",children:u})]})})]})]})}export{z as D};
