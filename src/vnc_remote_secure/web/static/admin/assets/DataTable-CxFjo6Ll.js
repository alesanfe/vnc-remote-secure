import{c,u as D,r as u,j as r}from"./index-CKYp4GNe.js";/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const N=c("ArrowDown",[["path",{d:"M12 5v14",key:"s699le"}],["path",{d:"m19 12-7 7-7-7",key:"1idqje"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const S=c("ArrowUp",[["path",{d:"m5 12 7-7 7 7",key:"hav0vg"}],["path",{d:"M12 19V5",key:"x0mq9r"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const V=c("ChevronsUpDown",[["path",{d:"m7 15 5 5 5-5",key:"1hf1tw"}],["path",{d:"m7 9 5-5 5 5",key:"sgt6xg"}]]);function C({columns:i,rows:a,rowKey:h,loading:m=!1,error:p=!1,errorText:x,emptyText:y}){const{t:o}=D(),j=x??o("table.errorText"),f=y??o("table.emptyText"),[n,b]=u.useState(null),k=u.useMemo(()=>{if(!a||!n)return a;const e=i.find(s=>s.key===n.key);if(!(e!=null&&e.sortValue))return a;const t=n.dir==="asc"?1:-1;return[...a].sort((s,g)=>{const d=e.sortValue(s),l=e.sortValue(g);return d==null&&l==null?0:d==null?1:l==null?-1:typeof d=="number"&&typeof l=="number"?(d-l)*t:String(d).localeCompare(String(l))*t})},[a,n,i]),v=e=>b(t=>(t==null?void 0:t.key)!==e?{key:e,dir:"asc"}:t.dir==="asc"?{key:e,dir:"desc"}:null);return p?r.jsx("div",{className:"error-box",role:"alert",children:j}):m&&!a?r.jsx("div",{className:"muted",role:"status",children:o("common.loading")}):r.jsxs("table",{className:"data",children:[r.jsx("thead",{children:r.jsx("tr",{children:i.map(e=>{const t=(n==null?void 0:n.key)===e.key;return r.jsx("th",{"aria-sort":t?n.dir==="asc"?"ascending":"descending":void 0,children:e.sortValue?r.jsxs("button",{type:"button",className:"th-sort",onClick:()=>v(e.key),children:[e.header," ",t?n.dir==="asc"?r.jsx(S,{size:12,"aria-hidden":"true"}):r.jsx(N,{size:12,"aria-hidden":"true"}):r.jsx(V,{size:12,"aria-hidden":"true"})]}):e.header},e.key)})})}),r.jsxs("tbody",{children:[(k??[]).map(e=>r.jsx("tr",{children:i.map(t=>{var s;return r.jsx("td",{title:(s=t.title)==null?void 0:s.call(t,e),className:t.mono?"mono":void 0,children:t.render(e)},t.key)})},h(e))),a&&a.length===0&&r.jsx("tr",{children:r.jsx("td",{colSpan:i.length,className:"muted",children:f})})]})]})}export{C as D};
