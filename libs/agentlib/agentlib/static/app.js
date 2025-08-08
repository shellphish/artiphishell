import { h, render, Component } from 'https://esm.sh/preact';
import { useEffect, useRef } from 'https://esm.sh/preact/hooks';
import htm from 'https://esm.sh/htm';
import jsonview from 'https://esm.sh/@pgrabovets/json-view';


const ht = htm.bind(h);

window.async_sleep = function (ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

class Modal extends Component {
  constructor(props) {
    super(props);
    // State to control visibility of the modal
    this.state = { isOpen: true };
  }

  // Method to close the modal
  close_modal = () => {
    this.setState({ isOpen: false });
    if (this.props.close) {
      this.props.close();
    }
  }

  onkeydown = (e) => {
    if (e.key == 'Escape') {
      this.close_modal();
    }
  }

  render_body() {
    return this.props.children;
  }

  render({ title, children }, { isOpen }) {
    useEffect(() => {
      document.addEventListener('keydown', this.onkeydown);
      return () => {
        document.removeEventListener('keydown', this.onkeydown);
      }
    }, []);
    return isOpen && ht`
      <div class="modal is-active">
        <div class="modal-background" onClick=${this.close_modal}></div>
        <div class="modal-card is-wide-modal">
          <header class="modal-card-head">
            <p class="modal-card-title">${title}</p>
            <button class="delete is-medium" aria-label="close" onClick=${this.close_modal}></button>
          </header>
          <section class="modal-card-body">
            ${this.render_body()}
          </section>
        </div>
      </div>
    `;
  }

  static with(body) {
    return ht`<${Modal}>${body}</${Modal}>`;
  }
}

const JsonViewer = ({ data }) => {
  if (data === undefined) {
    return ht`<small>Missing Data...</small>`;
  }
  if (typeof data === 'string') {
    return wrap_pre(data);
  }

  const jsonRef = useRef(null);
  let tree = null;

  useEffect(() => {
    renderJsonTree();

    return () => {
      destroyJsonTree();
    };
  }, [data]);

  const renderJsonTree = () => {
    const jsonElement = jsonRef.current;

    if (tree) {
      destroyJsonTree();
    }

    tree = jsonview.create(data);
    jsonview.render(tree, jsonElement);
    jsonview.toggleNode(tree);
  };

  const destroyJsonTree = () => {
    if (tree) {
      jsonview.destroy(tree);
      tree = null;
    }
  };

  return ht`<div ref=${jsonRef} className="json-viewer" />`;
};

export default JsonViewer;

class RecordDetails extends Component {
  static from_record(record) {
    let cls = record.get_details_class();
    let props = {...record.props};
    delete props.parent;
    return new cls(props);
  }
  modal(title) {
    let m = Modal.with(this.render());
    m.props.title = title || 'Record Details';
    return m;
  }
  render_body() {
    return ''
  }
  render_raw() {
    return ht` 
      <hr />
      <h4 class="title is-4">Raw Record</h4>
      <${JsonViewer} data=${this.props} />
      <hr />
      <pre>${JSON.stringify(this.props, null, 2)}</pre>
    `;
  }
  render() {
    return ht`
      <div>
        ${this.render_body()}
        ${this.render_raw()}
      </div>
    `;
  }
}

class Record extends Component {
  get_root_app() {
    if (!this.props.parent) {
      return null;
    }
    return this.props.parent.get_root_app();
  }

  get_details_class() {
    return RecordDetails;
  }

  static get_class_by_name(name) {
    if (name == 'AgentRecord')
      return AgentRecord;
    if (name == 'SequenceRecord')
      return SequenceRecord;
    if (name == 'ToolExecutorRecord')
      return AgentToolRunnerRecord;
    if (name == 'LLMInvocationRecord')
      return LLMInvocationRecord;
    if (name == 'ChatPromptTemplateRecord')
      return PromptRecord;
    if (name == 'ToolCallRecord')
      return ToolCallRecord;
    if (name == 'OutputParserRecord')
      return OutputParserRecord;
    if (name == 'AgentAnnotationRecord')
      return AgentAnnotationRecord;
    if (name == 'Record')
      return Record;
    console.error('Unknown class name', name);
    return Record;
  }

  constructor() {
    super();
  }

  static from_server_json(rj, cls=null, parent=null, index=null) {
    if (rj == null) {
      return null;
    }
    if (!cls) {
      cls = this.get_class_by_name(rj.name);
    }

    let r = new cls();
    r.id = rj.id;
    let children =  rj.children || [];

    r.props = {
      children_json: children,
    }
    if (rj.data) {
      for (let [k, v] of Object.entries(rj.data)) {
        r.props[k] = v;
      }
    }
    r.props.parent = parent;
    r.parent = parent;
    r.sibling_index = index;
    return r;
    // TODO decode input and output
  }
  display() {
    this.get_root_app().launch_modal(
      RecordDetails.from_record(this).modal()
    );
  }
  render() {
    return ht`<div
      class="card column record-card"
      style="width: ${this.get_width()}"
      data-class-name="Record"
      onclick="${this.display.bind(this)}"
    >
      <div class="card-content">
        <div class="content">
          <p class="tag is-danger mb-5">Unknown</p>
        </div>
      </div>
    </div>`;
  }
  get_width() {
    return this.props.width || this.get_min_width();
  }
  get_min_width() {
    return 100;
  }
}

// Main css framework for all components
//<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@1.0.0/css/bulma.min.css">


class SequenceRecord extends Record {
  should_have_output() {
    let children = this.props.children_json;
    if (children.length == 0) {
      return false;
    }
    let last_child = children[children.length - 1];
    last_child = Record.from_server_json(last_child);
    if (
      last_child &&
      last_child instanceof OutputParserRecord
    ) {
      return false;
    }
    if (this.parent) {
      let ind = this.sibling_index;
      let next_ind = ind + 1;
      let sibs = this.parent.props.children_json || [];
      if (next_ind < sibs.length) {
        return false;
      }
    }
    return true;
  }
  calculate_sub_widths() {
    let sum = 0;
    let widths = [];
    let max_width = window.innerWidth;

    let arrow_size = 25;

    for (let rj of this.props.children_json) {
      let record = Record.from_server_json(rj);
      let mw = record.get_min_width() + arrow_size;
      sum += mw;
      widths.push(rj);
    }

    sum -= arrow_size;

    sum += this.get_padding();

    if (this.should_have_output()) {
      sum += 100 + arrow_size;
    }

    return sum;
  }
  get_min_width() {
    if (this.props.width) {
      return this.props.width;
    }
    return this.calculate_sub_widths();
  }
  get_title() {
    return '';
  }
  get_padding() {
    return 0;
  }

  render() {
    let children = this.props.children_json.map((rj, i) => {
      let record = Record.from_server_json(rj, null, this, i);
      return ht`
        ${i>0? ht`<span class="icon"><i class="fa fa-arrow-right"></i></span>`:''}
        ${record.render()}
      `;
    });
    let output = this.props.output;
    let width = this.get_width();

    // If the last step in the chain is an OutputParser, then we don't need to show the output
    let should_have_output = this.should_have_output();
    if (!should_have_output) {
      output = '';
    } else {
      width -= 100 + 25;
    }

    return ht`
      <div class="card mb-3" style="width: ${width}px" data-class-name="${this.constructor.name}" data-has-output=${should_have_output}>
        <div class="card-content">
          ${this.get_title()}
          <div class="content record-row">
            ${children}
          </div>
        </div>
      </div>
      ${output? ht`<span class="icon"><i class="fa fa-arrow-right"></i></span>` : ''}
      <${ChainOutput} output=${output} />
    `;
  }
}

class AgentToolRunnerRecord extends SequenceRecord {
  get_title() {
    return ht`
    <p class="tag is-dark mb-5">Agent Tool Runner</p>
    `;
  }
}

class SingleRecord extends Record {
}

class ChainOutput extends SingleRecord {
  render() {
    if (!this.props.output) {
      return '';
    }
    return ht`
    <div
      class="card mb-3 output-card"
      style="width: ${this.get_width()}px"
      onclick="${this.display.bind(this)}"
    >
      <div class="card-content pl-2 pt-2">
        <div class="content">
          <p class="tag is-dark mb-5">Output</p>
        </div>
      </div>
    </div>
    `
  }
}

function wrap_pre(text) {
  if (!text) {
    return ht`<small>Missing Data...</small>`;
  }
  return ht`<pre style="text-wrap: pretty;">${text}</pre>`;
}

class PromptRecordDetails extends RecordDetails {
  render_body() {
    let out = [];
    let msgs = this.props.messages || [];
    for (let msg of msgs) {
      let cls_name = msg.id.slice(-1)[0];
      let msg_template = '';
      let template_type = null;
      if (cls_name == 'MessagesPlaceholder') {
        msg_template = `{{ ${msg.kwargs.variable_name} }}`;
      } else {
        let tpl = msg.kwargs.prompt.kwargs;
        msg_template = tpl.template;
        template_type = tpl.template_format;
      }
      out.push(ht`
        <h5 class="subtitle is-5 mb-0 mt-3">${cls_name}</h5>
        ${wrap_pre(msg_template, template_type)}
      `
      );
    }
    return ht`
        <h4 class="title is-4">Prompt Templates</h4>
        ${out}
        <h4 class="title is-4">Input Variables</h4>
        ${ht`<${JsonViewer} data=${this.props.input} />`}
    `;
  }
}

class PromptRecord extends SingleRecord {
  get_details_class() {
    return PromptRecordDetails;
  }
  display() {
    this.get_root_app().launch_modal(
      RecordDetails.from_record(this).modal()
    );
  }
  render() {
    return ht`
      <div
        class="card record-card"
        style="width: ${this.get_width()}px"
        data-class-name="PromptRecord"
        onclick="${this.display.bind(this)}"
      >
        <div class="card-content pl-2 pt-2">
          <div class="content" >
            <p class="tag is-info mb-5">Prompt</p>
          </div>
        </div>
      </div>
    `;
  }
}

class OutputRecordDetails extends RecordDetails {
  render_body() {
    let out = this.props.output;
    let content = '';
    let class_name = this.props.class_name;
    if (typeof out == 'string' || typeof out == 'undefined') {
      content = wrap_pre(out);
    } else if (class_name.indexOf('CodeExtractor') > -1) {
      let code = out.kwargs.source_code;
      let lang = out.kwargs.language;
      content = wrap_pre(code);
    } else if (class_name == 'PydanticOutputParser') {
      content = ht`
        <p class="subtitle is-5">Python Type: <code>${out.id.join('.')}</code></p>
        <${JsonViewer} data=${out.kwargs} />
      `;
    } else {
      content = ht`<${JsonViewer} data=${out} />`;
    }

    return ht`
      <h4 class="title is-4">${this.props.class_name}</h4>
      ${content}
    `;
  }
}

class OutputParserRecord extends SingleRecord {
  get_details_class() {
    return OutputRecordDetails;
  }
  render() {
    let name = this.props.class_name;
    if (name == 'JsonOutputParser') {
      name = 'JSON';
    }
    if (name == 'PlainTextOutputParser') {
      name = 'Text';
    }
    if (name == 'PydanticOutputParser' && this.props.output) {
      name = this.props.output.id.slice(-1)[0];
    }
    return ht`
      <div
        class="card record-card"
        style="width: ${this.get_width()}px"
        data-class-name="OutputParserRecord"
        onclick="${this.display.bind(this)}"
      >
        <div class="card-content pl-2 pt-2">
          <div class="content">
            <p class="tag is-dark mb-5">${name}</p>
          </div>
        </div>
      </div>
    `;
  }
}

class ToolCallRecord extends SingleRecord {
  render() {
    return ht`
      <div
        class="card record-card"
        style="width: ${this.get_width()}px"
        data-class-name="ToolCallRecord"
        onclick="${this.display.bind(this)}"
      >
        <div class="card-content pl-2 pt-2">
          <div class="content">
          <div class="tags">
            <span class="tag is-warning">Tool</span>
            <span class="tag is-warning">${this.props.tool.name}</span>
          </div>
          </div>
        </div>
      </div>
    `;
  }
}

class LLMInvocationRecordDetails extends RecordDetails {
  render_body() {
    let out = this.props.output?.content;
    let in_ = this.props.input?.join('\n\n\n');
    return ht`
      <h2 class="title is-2"><code>${this.props.model}</code> Invocation</h2>
      <h4 class="title is-4">LLM Output</h4>
      ${wrap_pre(out)}
      <hr />
      <h4 class="title is-4">LLM Input</h4>
      ${wrap_pre(in_)}
    `
  }
}

const ANNO_SEV_MAP = {
  'info': 'is-info',
  'code_exec': 'is-info',

  'warning': 'is-warning',

  'danger': 'is-danger',
  'exception': 'is-danger',
  'failure': 'is-danger',
  'fail': 'is-danger',
  'failed': 'is-danger',
  'error': 'is-danger',
  'bug': 'is-danger',
  'issue': 'is-danger',
  'problem': 'is-danger',
  'critical': 'is-danger',
  'fatal': 'is-danger',

  'primary': 'is-primary',

  'success': 'is-success',

  'link': 'is-link',
  'task': 'is-link',
}


class AgentAnnotationRecord extends SingleRecord {
  async reset_to_step() {
    if (!confirm('Are you sure you want to reset to this step? This cannot be undone!\nIMPORTANT! Make sure you are not running the agent right right now before proceeding!')) {
      return;
    }

    let target_plan = this.props.extra?.plan_id;
    if (target_plan === undefined) {
      alert('Could not find plan id');
      return;
    }
    let ind = this.props.extra?.step_index;
    if (ind === undefined) {
      alert('Could not find step index');
      return;
    }

    let res = await fetch(`/api/plan/${target_plan}/reset_to_step/${ind}`, {
      method: 'POST',
    });
    let j = {}
    try {
      j = await res.json();
    } catch (e) {
      alert('Error resetting agent: ' + e);
      return;
    }
    if (j.success) {
      alert('Agent reset to step ' + ind);
    } else {
      alert('Error resetting agent: ' + j.error);
    }
  }

  render() {
    let cls = 'is-link';

    let sev = this.props.severity;
    if (sev && ANNO_SEV_MAP[sev]) {
      cls = ANNO_SEV_MAP[sev];
    }

    if (this.props.annotation.startsWith('task_step')) {
      return ht`
        <hr />
        <article class="message ${cls} is-small mb-2 mt-3">
          <div class="message-body" style="padding: 1em;">
            <div class="is-flex is-flex-direction-row">
              <button 
                class="button mr-4"
                title="Reset to this step"
                onclick=${this.reset_to_step.bind(this)}
              >
                <i class="fa fa-fast-backward" aria-hidden="true"></i>
              </button>
              <div>
                <p class="subtitle is-5">${this.props.annotation}</p>
                ${this.props.input}
              </div>
            </div>
          </div>
        </article>
      `;

    }

    return ht`
      <hr />
      <article class="message ${cls} is-small mb-2 mt-3">
        <div class="message-body" style="padding: 1em;">
        <p class="subtitle is-5">${this.props.annotation}</p>
        ${this.props.input}
        </div>
      </article>
    `;
  }
}

class LLMInvocationRecord extends SingleRecord {
  get_details_class() {
    return LLMInvocationRecordDetails;
  }
  render() {
    return ht`
      <div
        class="card record-card"
        style="width: ${this.get_width()}px"
        data-class-name="LLMInvocationRecord"
        onclick="${this.display.bind(this)}"
      >
        <div class="card-content pl-2 pt-2">
          <div class="content">
            <p class="tag is-dark mb-5">${this.props.model}</p>
          </div>
        </div>
      </div>
    `;
  }
}

class AgentRecord extends Record {
  render() {
    let children = this.props.children_json.map((rj, ind) => {
      let record = Record.from_server_json(rj, null, this, ind);
      return ht`
        <div class="record-row top-level-record-row">
          ${record.render()}
        </div>
      `;
    });
    return ht`
      <div class="card mb-3" data-class-name="AgentRecord" style="width: 100%">
        <div class="card-content">
          <div class="content">
          <p class="subtitle">${this.props.class_name}</p>
          ${children}
          </div>
        </div>
      </div>
    `;
  }
}

function DisplayJson(props) {
  return ht`<pre class="json">${JSON.stringify(props.data, null, 2)}</pre>`;
}

class PopOver extends Component {
  constructor() {
    super();
    this.state = {

    };
  }
}




class App extends Component {
  constructor() {
    super();
    this.state = {
      tree: null,
      modal: null
    };
    this.load_tree();
  }

  get_root_app() {
    return this;
  }

  async load_tree() {
    const response = await fetch('/api/session/main/tree');
    const data = await response.json(); // TODO handle multiple top level agents correctly
    this.setState({tree: data});
  }

  launch_modal(modal) {
    if (modal) {
      modal.props.close = () => {
        this.launch_modal(null);
      }
    }
    this.setState({modal});
  }

  render() {
    useEffect(() => {
      const id = setInterval(() => {
        this.load_tree();
      }, 3000);
      return () => clearInterval(id);
    }, []);

    let children = this.state.tree || [];

    // Make a deep copy of the children so we can modify them
    children = JSON.parse(JSON.stringify(children));

    let top_level_children = [];

    // See if we have multiple calls to the same agent instance in a row. If so then we can merge them
    let prev = null;
    for (let ind = 0; ind < children.length; ind++) {
      let curr = children[ind];

      if (prev && prev.data.agent_id && curr.data.agent_id) {
        if (prev.data.agent_id == curr.data.agent_id) {
          if (!curr.children)
            continue;
          if (!prev.children)
            prev.children = [];
          prev.children.push(...curr.children);
          continue;
        }
      }

      top_level_children.push(curr);
      prev = curr;
    }

    let rendered_children = [];
    for (let ind = 0; ind < top_level_children.length; ind++) {
      let rj = top_level_children[ind];
      let record = Record.from_server_json(rj, null, this, ind);
      let res = ht`
        <section class="section">
          <div class="record-row">
          ${record.render()}
          </div>
        </section>
      `;
      rendered_children.push(res);
    }
      
    return ht`
      <div>
        <h1 class="title">AgentViz</h1>
        ${rendered_children}
        ${this.state.modal || ''}
      </div>
    `
  }
}

async function main() {
  render(ht`<${App} />`, document.getElementById('app'));
}
main();