import { Page } from "puppeteer";

class Lure {
    private page: Page;
 
    constructor(page: Page) {
        this.page = page;
    }

    private async _forms_lure() {
        const inputs = await this.page.$$("input");
        for (const _i in inputs) {
            await inputs[_i].type(`fake_input_from_sandbox_${_i}`)
        }
    
        const forms = await this.page.$$("form");
        for (const _f of forms) {
            await _f.evaluate((_form: HTMLFormElement) => {
                _form.submit()
            })
        }
        console.log("[analysis-debug] forms lure finished")
    }

    public async start_lure() {
        await this._forms_lure()
    }
}

export {
    Lure
}