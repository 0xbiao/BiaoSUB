/**
 * Cloudflare Worker: Sub-Manager Panel
 * 包含了前端 UI (Vue.js + Tailwind/DaisyUI) 和 后端 API
 */

const STORE_KEY_SUBS = 'SYSTEM_SUBSCRIPTIONS';
const STORE_KEY_NODES = 'SYSTEM_NODES';

// HTML 模板：前端页面
const html = `
<!DOCTYPE html>
<html lang="zh-CN" data-theme="cupcake">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>聚合订阅管理面板</title>
    <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.4.19/dist/full.min.css" rel="stylesheet" type="text/css" />
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/npm/remixicon@3.5.0/fonts/remixicon.css" rel="stylesheet">
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .fade-enter-active, .fade-leave-active { transition: opacity 0.3s ease; }
        .fade-enter-from, .fade-leave-to { opacity: 0; }
    </style>
</head>
<body class="bg-base-200 min-h-screen flex">

    <div id="app" class="flex w-full">
        
        <aside class="w-64 bg-base-100 text-base-content flex flex-col shadow-xl fixed h-full z-20 hidden lg:flex">
            <div class="p-6 text-center font-bold text-2xl text-primary border-b border-base-200">
                <i class="ri-earth-line mr-2"></i>SubManager
            </div>
            <ul class="menu p-4 w-full gap-2 text-lg">
                <li>
                    <a @click="currentTab = 'dashboard'" :class="{'active': currentTab === 'dashboard'}">
                        <i class="ri-dashboard-line"></i> 概览面板
                    </a>
                </li>
                <li class="menu-title mt-4">资源管理</li>
                <li>
                    <a @click="currentTab = 'subs'" :class="{'active': currentTab === 'subs'}">
                        <i class="ri-link-m"></i> 机场订阅
                    </a>
                </li>
                <li>
                    <a @click="currentTab = 'nodes'" :class="{'active': currentTab === 'nodes'}">
                        <i class="ri-server-line"></i> 独立节点
                    </a>
                </li>
                <li class="menu-title mt-4">设置</li>
                <li>
                    <a @click="currentTab = 'settings'" :class="{'active': currentTab === 'settings'}">
                        <i class="ri-settings-4-line"></i> 系统设置
                    </a>
                </li>
            </ul>
            <div class="mt-auto p-4 text-xs text-center text-base-content/50">
                v1.0.0 By Cloudflare Worker
            </div>
        </aside>

        <div class="lg:hidden fixed top-4 left-4 z-50">
             <div class="dropdown">
                <div tabindex="0" role="button" class="btn btn-ghost btn-circle bg-base-100 shadow">
                    <i class="ri-menu-line text-xl"></i>
                </div>
                <ul tabindex="0" class="menu menu-sm dropdown-content mt-3 z-[1] p-2 shadow bg-base-100 rounded-box w-52">
                    <li><a @click="currentTab = 'dashboard'">概览面板</a></li>
                    <li><a @click="currentTab = 'subs'">机场订阅</a></li>
                    <li><a @click="currentTab = 'nodes'">独立节点</a></li>
                </ul>
            </div>
        </div>

        <main class="flex-1 lg:ml-64 p-4 lg:p-8 overflow-y-auto h-screen">
            
            <div class="navbar bg-base-100 rounded-box shadow-sm mb-8">
                <div class="flex-1">
                    <a class="btn btn-ghost text-xl">欢迎回来，管理员</a>
                </div>
                <div class="flex-none gap-2">
                    <div class="dropdown dropdown-end">
                        <div tabindex="0" role="button" class="btn btn-ghost btn-circle avatar">
                            <div class="w-10 rounded-full bg-primary text-white flex items-center justify-center">
                                <span class="text-lg font-bold">A</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <transition name="fade" mode="out-in">
                
                <div v-if="currentTab === 'dashboard'" key="dashboard">
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                        <div class="stats shadow bg-base-100">
                            <div class="stat">
                                <div class="stat-figure text-primary">
                                    <i class="ri-link-m text-4xl"></i>
                                </div>
                                <div class="stat-title">订阅总数</div>
                                <div class="stat-value text-primary">{{ subs.length }}</div>
                                <div class="stat-desc">来自不同机场</div>
                            </div>
                        </div>
                        <div class="stats shadow bg-base-100">
                            <div class="stat">
                                <div class="stat-figure text-secondary">
                                    <i class="ri-server-line text-4xl"></i>
                                </div>
                                <div class="stat-title">独立节点</div>
                                <div class="stat-value text-secondary">{{ nodes.length }}</div>
                                <div class="stat-desc">手动添加的节点</div>
                            </div>
                        </div>
                        <div class="stats shadow bg-base-100">
                            <div class="stat">
                                <div class="stat-figure text-accent">
                                    <i class="ri-share-circle-line text-4xl"></i>
                                </div>
                                <div class="stat-title">聚合状态</div>
                                <div class="stat-value text-accent">运行中</div>
                                <div class="stat-desc">服务正常</div>
                            </div>
                        </div>
                    </div>

                    <div class="card bg-base-100 shadow-xl">
                        <div class="card-body">
                            <h2 class="card-title">快速指引</h2>
                            <p>欢迎使用聚合订阅管理面板。当前为基础版本，您可以在左侧菜单管理您的机场订阅链接和独立节点链接。后续将支持自动生成 v2rayN 和 Clash Verge 的聚合订阅地址。</p>
                            <div class="card-actions justify-end">
                                <button class="btn btn-primary" @click="currentTab = 'subs'">开始添加订阅</button>
                            </div>
                        </div>
                    </div>
                </div>

                <div v-else-if="currentTab === 'subs'" key="subs">
                    <div class="flex justify-between items-center mb-6">
                        <h2 class="text-2xl font-bold">机场订阅管理</h2>
                        <button class="btn btn-primary" onclick="sub_modal.showModal()">
                            <i class="ri-add-line"></i> 新增订阅
                        </button>
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
                        <div v-for="(sub, index) in subs" :key="sub.id" class="card bg-base-100 shadow-xl hover:shadow-2xl transition-shadow">
                            <div class="card-body">
                                <div class="flex justify-between items-start">
                                    <h2 class="card-title text-lg">{{ sub.name }}</h2>
                                    <div class="badge badge-outline badge-primary">{{ sub.type || 'General' }}</div>
                                </div>
                                <p class="text-sm text-base-content/70 truncate my-2 bg-base-200 p-2 rounded font-mono">{{ sub.url }}</p>
                                <p class="text-xs text-base-content/50">备注: {{ sub.remarks || '无' }}</p>
                                <div class="card-actions justify-end mt-4">
                                    <button class="btn btn-sm btn-ghost text-error" @click="deleteSub(sub.id)">删除</button>
                                </div>
                            </div>
                        </div>
                        <div v-if="subs.length === 0" class="col-span-full text-center py-10 text-base-content/50">
                            <i class="ri-inbox-line text-6xl"></i>
                            <p class="mt-2">暂无订阅数据，请点击右上角添加</p>
                        </div>
                    </div>
                </div>

                <div v-else-if="currentTab === 'nodes'" key="nodes">
                    <div class="flex justify-between items-center mb-6">
                        <h2 class="text-2xl font-bold">独立节点管理</h2>
                        <button class="btn btn-secondary" onclick="node_modal.showModal()">
                            <i class="ri-add-line"></i> 新增节点
                        </button>
                    </div>
                    
                    <div class="overflow-x-auto bg-base-100 rounded-box shadow-xl">
                        <table class="table">
                            <thead>
                                <tr class="bg-base-200">
                                    <th>名称</th>
                                    <th>链接预览 (vmess/vless/ss...)</th>
                                    <th>备注</th>
                                    <th>操作</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr v-for="node in nodes" :key="node.id" class="hover">
                                    <td class="font-bold">{{ node.name }}</td>
                                    <td>
                                        <div class="tooltip" :data-tip="node.link">
                                            <span class="badge badge-ghost cursor-pointer max-w-xs truncate block">{{ node.link.substring(0, 30) }}...</span>
                                        </div>
                                    </td>
                                    <td>{{ node.remarks || '-' }}</td>
                                    <td>
                                        <button class="btn btn-sm btn-circle btn-ghost text-error" @click="deleteNode(node.id)">
                                            <i class="ri-delete-bin-line"></i>
                                        </button>
                                    </td>
                                </tr>
                                <tr v-if="nodes.length === 0">
                                    <td colspan="4" class="text-center py-8 text-base-content/50">暂无独立节点</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <div v-else-if="currentTab === 'settings'" key="settings">
                     <div class="card bg-base-100 shadow-xl">
                        <div class="card-body">
                            <h2 class="card-title">系统设置</h2>
                            <p>这里将在后续用于配置聚合规则、API 密钥等信息。</p>
                        </div>
                    </div>
                </div>

            </transition>
        </main>
    </div>

    <dialog id="sub_modal" class="modal">
        <div class="modal-box">
            <h3 class="font-bold text-lg mb-4">添加新的订阅源</h3>
            <div class="flex flex-col gap-4">
                <input type="text" v-model="newSub.name" placeholder="机场名称 (例如: 飞天云)" class="input input-bordered w-full" />
                <input type="text" v-model="newSub.url" placeholder="订阅链接 (http/https)" class="input input-bordered w-full" />
                <input type="text" v-model="newSub.remarks" placeholder="备注信息 (可选)" class="input input-bordered w-full" />
            </div>
            <div class="modal-action">
                <form method="dialog">
                    <button class="btn btn-ghost">取消</button>
                    <button class="btn btn-primary ml-2" @click="addSub">保存</button>
                </form>
            </div>
        </div>
    </dialog>

    <dialog id="node_modal" class="modal">
        <div class="modal-box">
            <h3 class="font-bold text-lg mb-4">添加独立节点</h3>
            <div class="flex flex-col gap-4">
                <input type="text" v-model="newNode.name" placeholder="节点名称" class="input input-bordered w-full" />
                <textarea v-model="newNode.link" class="textarea textarea-bordered h-24" placeholder="节点链接 (vmess://..., ss://...)"></textarea>
                <input type="text" v-model="newNode.remarks" placeholder="备注信息 (可选)" class="input input-bordered w-full" />
            </div>
            <div class="modal-action">
                <form method="dialog">
                    <button class="btn btn-ghost">取消</button>
                    <button class="btn btn-secondary ml-2" @click="addNode">保存</button>
                </form>
            </div>
        </div>
    </dialog>

    <script>
        const { createApp, ref, onMounted } = Vue;

        createApp({
            setup() {
                const currentTab = ref('dashboard');
                
                // 数据模型
                const subs = ref([]);
                const nodes = ref([]);

                // 新增表单数据
                const newSub = ref({ name: '', url: '', remarks: '' });
                const newNode = ref({ name: '', link: '', remarks: '' });

                // 加载数据
                const loadData = async () => {
                    try {
                        const res = await fetch('/api/data');
                        const data = await res.json();
                        subs.value = data.subs || [];
                        nodes.value = data.nodes || [];
                    } catch (e) {
                        console.error("加载失败", e);
                    }
                };

                // 添加订阅
                const addSub = async () => {
                    if(!newSub.value.name || !newSub.value.url) return alert("请填写完整");
                    const payload = { 
                        id: Date.now().toString(), 
                        ...newSub.value, 
                        type: 'Subscription' 
                    };
                    
                    // 更新本地视图
                    subs.value.push(payload);
                    
                    // 提交后端
                    await saveData();
                    
                    // 清空表单
                    newSub.value = { name: '', url: '', remarks: '' };
                };

                // 删除订阅
                const deleteSub = async (id) => {
                    if(!confirm('确定删除?')) return;
                    subs.value = subs.value.filter(s => s.id !== id);
                    await saveData();
                };

                // 添加节点
                const addNode = async () => {
                    if(!newNode.value.name || !newNode.value.link) return alert("请填写完整");
                    const payload = {
                        id: Date.now().toString(),
                        ...newNode.value
                    };
                    nodes.value.push(payload);
                    await saveData();
                    newNode.value = { name: '', link: '', remarks: '' };
                };

                // 删除节点
                const deleteNode = async (id) => {
                    if(!confirm('确定删除?')) return;
                    nodes.value = nodes.value.filter(n => n.id !== id);
                    await saveData();
                };

                // 核心：保存数据到后端
                const saveData = async () => {
                    await fetch('/api/save', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            subs: subs.value,
                            nodes: nodes.value
                        })
                    });
                };

                onMounted(() => {
                    loadData();
                });

                return {
                    currentTab,
                    subs,
                    nodes,
                    newSub,
                    newNode,
                    addSub,
                    deleteSub,
                    addNode,
                    deleteNode
                };
            }
        }).mount('#app');
    </script>
</body>
</html>
`;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // 1. 路由：获取数据 API
    if (path === '/api/data') {
      const subs = await env.SUB_STORE.get(STORE_KEY_SUBS, { type: 'json' });
      const nodes = await env.SUB_STORE.get(STORE_KEY_NODES, { type: 'json' });
      return new Response(JSON.stringify({ 
        subs: subs || [], 
        nodes: nodes || [] 
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 2. 路由：保存数据 API
    if (path === '/api/save' && request.method === 'POST') {
      try {
        const data = await request.json();
        // 并行写入 KV
        await Promise.all([
            env.SUB_STORE.put(STORE_KEY_SUBS, JSON.stringify(data.subs)),
            env.SUB_STORE.put(STORE_KEY_NODES, JSON.stringify(data.nodes))
        ]);
        return new Response(JSON.stringify({ success: true }), {
            headers: { 'Content-Type': 'application/json' }
        });
      } catch (e) {
        return new Response(JSON.stringify({ success: false, error: e.message }), { status: 500 });
      }
    }

    // 3. 默认路由：返回 HTML 页面
    return new Response(html, {
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
      },
    });
  },
};
