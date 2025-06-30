import { Page } from "puppeteer";

// Lure tries to trigger possibly hidden functionalities
// of the sample by performing actions on the page 
// (e.g. submit the form found on the loaded page)
class Lure {
    private page: Page;
 
    constructor(page: Page) {
        this.page = page;
    }

    // find a form, place dummy input and submit it
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
    }

    public async start_lure() {
        await this._forms_lure()
    }
}

export {
    Lure
}