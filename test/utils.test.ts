import { getFindClientFn } from '../src/utils';

describe('getFindClientFn', () => {
  it('throws if neither of input params exist', () => {
    expect(getFindClientFn).toThrow();
  });
  it('returns first parameter if only that exists', () => {
    const findClientFn: any = () => {};
    expect(getFindClientFn(findClientFn)).toEqual(findClientFn);
  });
});
