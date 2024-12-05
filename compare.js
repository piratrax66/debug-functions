function compare(a, b) {
    // Handle undefined and null values first
    if (a === undefined || a === null) {
        return b === undefined || b === null;
    }
    if (b === undefined || b === null) {
        return false;
    }

    // Check if arrays
    if (Array.isArray(a) && Array.isArray(b)) {
        if (a.length !== b.length) {
            return false;
        }
        for (let i = 0; i < a.length; i++) {
            if (!compare(a[i], b[i])) {
                return false;
            }
        }
        return true;
    }

    // Check if objects (but not arrays)
    if (typeof a === 'object' && typeof b === 'object') {
        const keysA = Object.keys(a);
        const keysB = Object.keys(b);

        if (keysA.length !== keysB.length) {
            return false;
        }

        for (const key of keysA) {
            if (!compare(a[key], b[key])) {
                return false;
            }
        }
        return true;
    }

    // Simple value comparison
    return a === b;
}

// Test cases
console.log(compare(null, null)); // Should print: true
console.log(compare(undefined, undefined)); // Should print: true
console.log(compare(null, undefined)); // Should print: true
console.log(compare({a: null}, {a: null})); // Should print: true
console.log(compare([null], [null])); // Should print: true
console.log(compare({a: 1}, {a: null})); // Should print: false