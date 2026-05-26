// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Abstractions;
using ChuA.Authentication.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace ChuA.Authentication.Tests;

public sealed class ClaimsTransformationTests
{
    [Fact]
    public async Task TransformAsyncRunsMappingWhenNoEnrichersAreRegistered()
    {
        var mappedPrincipal = CreatePrincipal("mapped");
        var transformation = CreateTransformation(new TestClaimsMappingService(mappedPrincipal));

        var result = await transformation.TransformAsync(CreatePrincipal("original"));

        Assert.Same(mappedPrincipal, result);
        Assert.Contains(result.Claims, claim => claim.Type == "stage" && claim.Value == "mapped");
    }

    [Fact]
    public async Task TransformAsyncRunsOneEnricherAfterMapping()
    {
        var mappedPrincipal = CreatePrincipal("mapped");
        var enricher = new RecordingClaimsEnricher("enriched");
        var transformation = CreateTransformation(new TestClaimsMappingService(mappedPrincipal), enricher);

        var result = await transformation.TransformAsync(CreatePrincipal("original"));

        Assert.Same(mappedPrincipal, enricher.ReceivedPrincipals.Single());
        Assert.Same(mappedPrincipal, result);
        Assert.Contains(result.Claims, claim => claim.Type == "stage" && claim.Value == "mapped");
        Assert.Contains(result.Claims, claim => claim.Type == "stage" && claim.Value == "enriched");
    }

    [Fact]
    public async Task TransformAsyncRunsMultipleEnrichersInRegistrationOrder()
    {
        var mappedPrincipal = CreatePrincipal("mapped");
        var first = new RecordingClaimsEnricher("first");
        var second = new RecordingClaimsEnricher("second");
        var transformation = CreateTransformation(new TestClaimsMappingService(mappedPrincipal), first, second);

        var result = await transformation.TransformAsync(CreatePrincipal("original"));

        Assert.Same(mappedPrincipal, result);
        Assert.Collection(
            result.Claims.Where(claim => claim.Type == "stage").Select(claim => claim.Value),
            value => Assert.Equal("mapped", value),
            value => Assert.Equal("first", value),
            value => Assert.Equal("second", value));
    }

    [Fact]
    public async Task TransformAsyncPassesPrincipalReturnedByPreviousEnricher()
    {
        var replacementPrincipal = CreatePrincipal("replacement");
        var returningEnricher = new ReturningClaimsEnricher(replacementPrincipal);
        var receivingEnricher = new RecordingClaimsEnricher("after-replacement");
        var transformation = CreateTransformation(
            new TestClaimsMappingService(CreatePrincipal("mapped")),
            returningEnricher,
            receivingEnricher);

        var result = await transformation.TransformAsync(CreatePrincipal("original"));

        Assert.Same(replacementPrincipal, receivingEnricher.ReceivedPrincipals.Single());
        Assert.Same(replacementPrincipal, result);
        Assert.Contains(result.Claims, claim => claim.Type == "stage" && claim.Value == "after-replacement");
    }

    [Fact]
    public async Task TransformAsyncReturnsStoredPrincipalDuringReentry()
    {
        var mappedPrincipal = CreatePrincipal("mapped");
        var httpContextAccessor = new HttpContextAccessor { HttpContext = new DefaultHttpContext() };
        var mappingService = new TestClaimsMappingService(mappedPrincipal);
        var reentrantEnricher = new ReentrantClaimsEnricher();
        var transformation = new ChuAClaimsTransformation(mappingService, [reentrantEnricher], httpContextAccessor);
        reentrantEnricher.ReenterAsync = () => transformation.TransformAsync(CreatePrincipal("reentrant"));

        var result = await transformation.TransformAsync(CreatePrincipal("original"));

        Assert.Equal(1, reentrantEnricher.InvocationCount);
        Assert.Same(mappedPrincipal, reentrantEnricher.ReentrantPrincipal);
        Assert.Same(mappedPrincipal, result);
        Assert.Contains(result.Claims, claim => claim.Type == "stage" && claim.Value == "mapped");
        Assert.Contains(result.Claims, claim => claim.Type == "stage" && claim.Value == "enriched-after-reentry");
    }

    private static ChuAClaimsTransformation CreateTransformation(
        IClaimsMappingService claimsMappingService,
        params IClaimsEnricher[] claimsEnrichers)
        => new(claimsMappingService, claimsEnrichers, new HttpContextAccessor());

    private static ClaimsPrincipal CreatePrincipal(string stage)
        => new(new ClaimsIdentity([new Claim("stage", stage)], "Test"));

    private sealed class TestClaimsMappingService(ClaimsPrincipal mappedPrincipal) : IClaimsMappingService
    {
        public ClaimsPrincipal MapClaims(ClaimsPrincipal principal)
            => mappedPrincipal;

        public IReadOnlyCollection<string> GetRoles(ClaimsPrincipal principal)
            => [];

        public IReadOnlyCollection<string> GetPermissions(ClaimsPrincipal principal)
            => [];

        public IReadOnlyCollection<string> GetScopes(ClaimsPrincipal principal)
            => [];
    }

    private sealed class RecordingClaimsEnricher(string stage) : IClaimsEnricher
    {
        public List<ClaimsPrincipal> ReceivedPrincipals { get; } = [];

        public Task<ClaimsPrincipal> EnrichAsync(ClaimsPrincipal principal)
        {
            ReceivedPrincipals.Add(principal);
            principal.Identities.First().AddClaim(new Claim("stage", stage));
            return Task.FromResult(principal);
        }
    }

    private sealed class ReturningClaimsEnricher(ClaimsPrincipal returnedPrincipal) : IClaimsEnricher
    {
        public Task<ClaimsPrincipal> EnrichAsync(ClaimsPrincipal principal)
            => Task.FromResult(returnedPrincipal);
    }

    private sealed class ReentrantClaimsEnricher : IClaimsEnricher
    {
        public Func<Task<ClaimsPrincipal>> ReenterAsync { get; set; } = () => Task.FromResult(new ClaimsPrincipal());
        public int InvocationCount { get; private set; }
        public ClaimsPrincipal? ReentrantPrincipal { get; private set; }

        public async Task<ClaimsPrincipal> EnrichAsync(ClaimsPrincipal principal)
        {
            InvocationCount++;
            ReentrantPrincipal = await ReenterAsync();
            principal.Identities.First().AddClaim(new Claim("stage", "enriched-after-reentry"));
            return principal;
        }
    }
}
