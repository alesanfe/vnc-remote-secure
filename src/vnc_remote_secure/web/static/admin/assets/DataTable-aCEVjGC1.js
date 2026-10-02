import{c,u as C,r as m,j as r}from"./index-Bu_gJaaF.js";/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const S=c("ArrowDown",[["path",{d:"M12 5v14",key:"s699le"}],["path",{d:"m19 12-7 7-7-7",key:"1idqje"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const V=c("ArrowUp",[["path",{d:"m5 12 7-7 7 7",key:"hav0vg"}],["path",{d:"M12 19V5",key:"x0mq9r"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const U=c("ChevronsUpDown",[["path",{d:"m7 15 5 5 5-5",key:"1hf1tw"}],["path",{d:"m7 9 5-5 5 5",key:"sgt6xg"}]]);function A({columns:i,rows:a,rowKey:x,loading:p=!1,error:j=!1,errorText:y,onRetry:u,emptyText:f,emptyAction:h}){const{t:d}=C(),b=y??d("table.errorText"),k=f??d("table.emptyText"),[n,v]=m.useState(null),g=m.useMemo(()=>{if(!a||!n)return a;const e=i.find(s=>s.key===n.key);if(!(e!=null&&e.sortValue))return a;const t=n.dir==="asc"?1:-1;return[...a].sort((s,D)=>{const l=e.sortValue(s),o=e.sortValue(D);return l==null&&o==null?0:l==null?1:o==null?-1:typeof l=="number"&&typeof o=="number"?(l-o)*t:String(l).localeCompare(String(o))*t})},[a,n,i]),N=e=>v(t=>(t==null?void 0:t.key)!==e?{key:e,dir:"asc"}:t.dir==="asc"?{key:e,dir:"desc"}:null);return j?r.jsxs("div",{className:"error-box",role:"alert",children:[b,u&&r.jsx("button",{type:"button",className:"ghost",onClick:u,children:d("common.retry")})]}):p&&!a?r.jsx("div",{className:"muted",role:"status",children:d("common.loading")}):r.jsxs("table",{className:"data",children:[r.jsx("thead",{children:r.jsx("tr",{children:i.map(e=>{const t=(n==null?void 0:n.key)===e.key;return r.jsx("th",{"aria-sort":t?n.dir==="asc"?"ascending":"descending":void 0,children:e.sortValue?r.jsxs("button",{type:"button",className:"th-sort",onClick:()=>N(e.key),children:[e.header," ",t?n.dir==="asc"?r.jsx(V,{size:12,"aria-hidden":"true"}):r.jsx(S,{size:12,"aria-hidden":"true"}):r.jsx(U,{size:12,"aria-hidden":"true"})]}):e.header},e.key)})})}),r.jsxs("tbody",{children:[(g??[]).map(e=>r.jsx("tr",{children:i.map(t=>{var s;return r.jsx("td",{title:(s=t.title)==null?void 0:s.call(t,e),className:t.mono?"mono":void 0,children:t.render(e)},t.key)})},x(e))),a&&a.length===0&&r.jsx("tr",{children:r.jsxs("td",{colSpan:i.length,className:"muted",children:[k,h&&r.jsx("div",{className:"empty-action",children:h})]})})]})]})}export{A as D};
