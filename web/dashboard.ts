type DashboardVM = {
  name: string;
  ip: string;
  rdpHost: string;
  state: string;
  memoryMiB: number;
  vcpu: number;
  volumeGB: number;
};

type DashboardDataResponse = {
  filename: string;
  vms: DashboardVM[];
  error?: string;
};

type ActionResponse = {
  ok: boolean;
  message?: string;
  error?: string;
};

type JsonResult<T> = {
  ok: boolean;
  data?: T;
  error?: string;
};

type State = {
  vms: DashboardVM[];
  filename: string;
  vmError: string;
  actionMessage: string;
  actionError: string;
  loading: boolean;
  busy: boolean;
};

const DEFAULT_VM_ERROR = "Unable to load virtual machines right now.";

const state: State = {
  vms: [],
  filename: "rdpgw.rdp",
  vmError: "",
  actionMessage: "",
  actionError: "",
  loading: true,
  busy: false,
};

function bootstrap(): void {
  const root = document.getElementById("app");
  if (!root) {
    return;
  }

  root.innerHTML = `
    <main class="card">
      <section class="vm-panel">
        <div class="vm-header">
          <h2>Available VMs</h2>
          <a class="logout-button" href="/logout">Logout</a>
        </div>
        <p class="vm-subtitle">Live inventory from libvirt.</p>
        <form class="vm-form" id="create-form">
          <div class="field">
            <label for="vm-name">New VM Name</label>
            <input id="vm-name" name="vm_name" autocomplete="off" pattern="[A-Za-z0-9_-]+" maxlength="64" title="Letters, numbers, '-' or '_' only" required>
          </div>
          <button id="create-button" type="submit">Create VM</button>
        </form>
        <div id="action-area" aria-live="polite"></div>
        <div id="vm-list"></div>
      </section>
    </main>
  `;

  const form = root.querySelector<HTMLFormElement>("#create-form");
  const input = root.querySelector<HTMLInputElement>("#vm-name");
  const createButton = root.querySelector<HTMLButtonElement>("#create-button");
  const actionArea = root.querySelector<HTMLDivElement>("#action-area");
  const listArea = root.querySelector<HTMLDivElement>("#vm-list");

  if (!form || !input || !createButton || !actionArea || !listArea) {
    return;
  }

  const formEl = form;
  const inputEl = input;
  const createButtonEl = createButton;
  const actionAreaEl = actionArea;
  const listAreaEl = listArea;

  function renderAction(): void {
    actionAreaEl.innerHTML = "";
    if (state.actionError) {
      const error = document.createElement("p");
      error.className = "vm-error";
      error.textContent = state.actionError;
      actionAreaEl.appendChild(error);
      return;
    }
    if (state.actionMessage) {
      const message = document.createElement("p");
      message.className = "vm-success";
      message.textContent = state.actionMessage;
      actionAreaEl.appendChild(message);
    }
  }

  function renderVMList(): void {
    listAreaEl.innerHTML = "";

    if (state.loading) {
      const loading = document.createElement("p");
      loading.className = "vm-loading";
      loading.textContent = "Loading virtual machines...";
      listAreaEl.appendChild(loading);
      return;
    }

    if (state.vmError) {
      const error = document.createElement("p");
      error.className = "vm-error";
      error.textContent = state.vmError;
      listAreaEl.appendChild(error);
      return;
    }

    if (state.vms.length === 0) {
      const empty = document.createElement("p");
      empty.className = "vm-empty";
      empty.textContent = "No virtual machines found.";
      listAreaEl.appendChild(empty);
      return;
    }

    const wrap = document.createElement("div");
    wrap.className = "vm-table-wrap";

    const table = document.createElement("table");
    table.className = "vm-table";

    const thead = document.createElement("thead");
    const headRow = document.createElement("tr");
    const columns = [
      "Name",
      "IP Address",
      "State",
      "Memory",
      "vCPU",
      "Disk",
      "Actions",
    ];
    for (const label of columns) {
      const th = document.createElement("th");
      th.textContent = label;
      headRow.appendChild(th);
    }
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement("tbody");
    for (const vm of state.vms) {
      const row = document.createElement("tr");

      const nameCell = document.createElement("td");
      nameCell.className = "vm-name";
      nameCell.textContent = vm.name || "n/a";
      row.appendChild(nameCell);

      const ipCell = document.createElement("td");
      ipCell.textContent = vm.ip || "n/a";
      row.appendChild(ipCell);

      const stateCell = document.createElement("td");
      stateCell.className = "vm-state";
      stateCell.textContent = vm.state || "n/a";
      row.appendChild(stateCell);

      const memoryCell = document.createElement("td");
      memoryCell.textContent = vm.memoryMiB ? `${vm.memoryMiB} MiB` : "n/a";
      row.appendChild(memoryCell);

      const vcpuCell = document.createElement("td");
      vcpuCell.textContent = vm.vcpu ? `${vm.vcpu}` : "n/a";
      row.appendChild(vcpuCell);

      const diskCell = document.createElement("td");
      diskCell.textContent = vm.volumeGB ? `${vm.volumeGB} GB` : "n/a";
      row.appendChild(diskCell);

      const actionCell = document.createElement("td");
      const actions = document.createElement("div");
      actions.className = "vm-actions";

      if (vm.rdpHost) {
        const download = document.createElement("a");
        download.className = "vm-download";
        download.href = `/api/${state.filename}?target=${encodeURIComponent(vm.rdpHost)}`;
        download.textContent = "Download";
        actions.appendChild(download);
      } else {
        const disabled = document.createElement("span");
        disabled.className = "vm-disabled";
        disabled.textContent = "n/a";
        actions.appendChild(disabled);
      }

      const removeButton = document.createElement("button");
      removeButton.type = "button";
      removeButton.className = "vm-remove";
      removeButton.textContent = "Remove";
      removeButton.disabled = state.busy;
      removeButton.addEventListener("click", () => {
        void removeVM(vm.name);
      });
      actions.appendChild(removeButton);

      actionCell.appendChild(actions);
      row.appendChild(actionCell);

      tbody.appendChild(row);
    }
    table.appendChild(tbody);
    wrap.appendChild(table);
    listAreaEl.appendChild(wrap);
  }

  function setBusy(isBusy: boolean): void {
    state.busy = isBusy;
    inputEl.disabled = isBusy;
    createButtonEl.disabled = isBusy;
    renderVMList();
  }

  function setActionError(message: string): void {
    state.actionError = message;
    state.actionMessage = "";
    renderAction();
  }

  function setActionMessage(message: string): void {
    state.actionMessage = message;
    state.actionError = "";
    renderAction();
  }

  function clearAction(): void {
    state.actionError = "";
    state.actionMessage = "";
    renderAction();
  }

  function applyInitialMessage(): void {
    const params = new URLSearchParams(window.location.search);
    if (params.has("removed")) {
      setActionMessage("VM removed.");
      params.delete("removed");
    } else if (params.has("created")) {
      setActionMessage("VM creation started.");
      params.delete("created");
    }

    if (params.toString() !== window.location.search.replace(/^\?/, "")) {
      const query = params.toString();
      const next = query ? `${window.location.pathname}?${query}` : window.location.pathname;
      window.history.replaceState({}, "", next);
    }
  }

  async function requestJSON<T>(url: string, init: RequestInit = {}): Promise<JsonResult<T> | null> {
    const headers = new Headers(init.headers);
    headers.set("Accept", "application/json");
    const response = await fetch(url, {
      ...init,
      headers,
      credentials: "same-origin",
    });

    if (response.redirected) {
      const redirectedUrl = new URL(response.url);
      if (redirectedUrl.pathname === "/login") {
        window.location.assign("/login");
        return null;
      }
    }

    let payload: unknown = null;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }

    if (!response.ok) {
      const errorMessage =
        payload && typeof (payload as { error?: string }).error === "string"
          ? (payload as { error: string }).error
          : "Request failed.";
      return { ok: false, error: errorMessage };
    }

    return { ok: true, data: payload as T };
  }

  async function loadVMs(): Promise<void> {
    state.loading = true;
    state.vmError = "";
    renderVMList();

    const result = await requestJSON<DashboardDataResponse>("/api/dashboard/data");
    if (!result) {
      return;
    }

    if (!result.ok || !result.data) {
      state.vmError = result.error || DEFAULT_VM_ERROR;
      state.loading = false;
      renderVMList();
      return;
    }

    state.vms = result.data.vms || [];
    if (result.data.filename) {
      state.filename = result.data.filename;
    }
    if (result.data.error) {
      state.vmError = result.data.error;
    }
    state.loading = false;
    renderVMList();
  }

  async function createVM(name: string): Promise<void> {
    if (state.busy) {
      return;
    }

    clearAction();
    setBusy(true);

    try {
      const body = new URLSearchParams({ vm_name: name });
      const result = await requestJSON<ActionResponse>("/api/dashboard", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
      });

      if (!result) {
        return;
      }

      if (!result.ok || !result.data) {
        setActionError(result.error || "Failed to create VM.");
        return;
      }

      if (!result.data.ok) {
        setActionError(result.data.error || "Failed to create VM.");
        return;
      }

      setActionMessage(result.data.message || "VM creation started.");
      inputEl.value = "";
      await loadVMs();
    } finally {
      setBusy(false);
    }
  }

  async function removeVM(name: string): Promise<void> {
    if (state.busy) {
      return;
    }

    clearAction();
    setBusy(true);

    try {
      const body = new URLSearchParams({ vm_name: name });
      const result = await requestJSON<ActionResponse>("/api/dashboard/remove", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
      });

      if (!result) {
        return;
      }

      if (!result.ok || !result.data) {
        setActionError(result.error || "Failed to remove VM.");
        return;
      }

      if (!result.data.ok) {
        setActionError(result.data.error || "Failed to remove VM.");
        return;
      }

      setActionMessage(result.data.message || "VM removed.");
      await loadVMs();
    } finally {
      setBusy(false);
    }
  }

  formEl.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!formEl.reportValidity()) {
      return;
    }
    void createVM(inputEl.value.trim());
  });

  applyInitialMessage();
  renderAction();
  renderVMList();
  void loadVMs();
}

bootstrap();
