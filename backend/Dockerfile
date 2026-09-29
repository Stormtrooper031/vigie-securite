# Contexte de build : racine du projet (pour inclure shared/)
#   docker build -f backend/Dockerfile .

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY shared/Vigie.Shared/Vigie.Shared.csproj shared/Vigie.Shared/
COPY backend/Vigie.Api.csproj backend/
RUN dotnet restore backend/Vigie.Api.csproj
COPY shared/ shared/
COPY backend/ backend/
RUN dotnet publish backend/Vigie.Api.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app .
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
# Utilisateur non-root fourni par l'image .NET
USER $APP_UID
ENTRYPOINT ["dotnet", "Vigie.Api.dll"]
